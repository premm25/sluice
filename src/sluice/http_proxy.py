"""Streamable HTTP transport: put Sluice in front of a *remote* MCP server.

    MCP client  --HTTP-->  sluice serve (127.0.0.1:8931/mcp)  --HTTPS-->  https://mcp.example.com/mcp

The client is pointed at the local URL instead of the remote one. Every
JSON-RPC message goes through the same :class:`~sluice.engine.Engine` as the
stdio proxy, in both directions:

* ``POST``   client messages; the upstream answers with ``application/json``
             or a ``text/event-stream`` whose events are inspected one by one
* ``GET``    the optional server-initiated event stream, inspected the same way
* ``DELETE`` session termination, passed through

Blocked calls are answered locally and never reach the upstream server.

Security: the proxy binds to 127.0.0.1 and, as the MCP spec requires,
rejects requests whose ``Origin`` is not local (DNS-rebinding protection) --
a missing local check of this kind is what made CVE-2025-49596 in the MCP
Inspector exploitable from a web page.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from sluice.engine import Engine
from sluice.policy import Policy
from sluice.store import Store

log = logging.getLogger("sluice")

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding", "origin",
}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
SESSION_HEADER = "Mcp-Session-Id"


def _dumps(msg: Any) -> bytes:
    return json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _flatten(items: list[Any]) -> list[Any]:
    out: list[Any] = []
    for item in items:
        out.extend(item if isinstance(item, list) else [item])
    return out


def _ids(msg: Any) -> list[Any]:
    msgs = msg if isinstance(msg, list) else [msg]
    return [m["id"] for m in msgs if isinstance(m, dict) and "id" in m and "method" in m]


def iter_sse(lines: Iterator[bytes]) -> Iterator[tuple[list[tuple[str, str]], str | None]]:
    """Yield ``(other_fields, data)`` per server-sent event."""
    fields: list[tuple[str, str]] = []
    data: list[str] = []
    for raw in lines:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            if fields or data:
                yield fields, "\n".join(data) if data else None
            fields, data = [], []
            continue
        if line.startswith(":"):
            continue  # comment / keep-alive
        name, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if name == "data":
            data.append(value)
        else:
            fields.append((name, value))
    if fields or data:
        yield fields, "\n".join(data) if data else None


def format_sse(fields: list[tuple[str, str]], data: str | None) -> bytes:
    out = "".join(f"{k}: {v}\n" for k, v in fields)
    if data is not None:
        out += "".join(f"data: {line}\n" for line in data.split("\n"))
    return (out + "\n").encode("utf-8")


class HttpProxy:
    def __init__(self, upstream: str, policy: Policy, store: Store, *, name: str = "remote",
                 session: str | None = None, path: str = "/mcp", allow_origins: tuple[str, ...] = (),
                 extra_headers: dict[str, str] | None = None, timeout: float = 600,
                 engine_factory: Callable[..., Engine] = Engine):
        self.upstream = upstream
        self.policy = policy
        self.store = store
        self.name = name
        self.session = session
        self.path = path
        self.allow_origins = set(allow_origins)
        self.extra_headers = extra_headers or {}
        self.timeout = timeout
        self._engine_factory = engine_factory
        self._engines: dict[str, Engine] = {}
        self._lock = threading.Lock()

    def engine(self, mcp_session: str | None) -> Engine:
        """One engine per MCP session (stateless servers share one)."""
        key = mcp_session or ""
        with self._lock:
            if key not in self._engines:
                self._engines[key] = self._engine_factory(self.policy, self.store, server=self.name,
                                                          session=self.session)
            return self._engines[key]

    def adopt(self, engine: Engine, mcp_session: str) -> None:
        with self._lock:
            self._engines.setdefault(mcp_session, engine)

    def forget(self, mcp_session: str | None) -> None:
        with self._lock:
            self._engines.pop(mcp_session or "", None)

    def origin_allowed(self, origin: str | None) -> bool:
        if not origin:
            return True  # non-browser clients send no Origin
        if origin in self.allow_origins:
            return True
        host = urlsplit(origin).hostname or ""
        return host in LOCAL_HOSTS

    def make_server(self, host: str = "127.0.0.1", port: int = 8931) -> ThreadingHTTPServer:
        proxy = self

        class Handler(_Handler):
            pass
        Handler.proxy = proxy
        server = ThreadingHTTPServer((host, port), Handler)
        server.daemon_threads = True
        return server


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    proxy: HttpProxy
    server_version = "sluice"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - signature from stdlib
        log.debug("http: " + format, *args)

    # -------------------------------------------------------------- helpers

    def _reject(self, status: int, message: str) -> None:
        body = _dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": message}})
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _guard(self) -> bool:
        if urlsplit(self.path).path != self.proxy.path:
            self._reject(404, f"sluice proxies MCP at {self.proxy.path}")
            return False
        if not self.proxy.origin_allowed(self.headers.get("Origin")):
            log.warning("rejected request from origin %s", self.headers.get("Origin"))
            self._reject(403, "origin not allowed")
            return False
        return True

    def _upstream(self, method: str, body: bytes | None = None) -> Any:
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
        headers.update(self.proxy.extra_headers)
        req = urllib.request.Request(self.proxy.upstream, data=body, method=method, headers=headers)
        try:
            return urllib.request.urlopen(req, timeout=self.proxy.timeout)
        except urllib.error.HTTPError as e:
            return e  # HTTPError is also a response: relay its status and body

    def _send_headers(self, status: int, upstream_headers: Any, content_type: str | None,
                      length: int | None) -> None:
        self.send_response(status)
        for k, v in upstream_headers.items():
            if k.lower() not in HOP_BY_HOP and k.lower() != "content-type":
                self.send_header(k, v)
        if content_type:
            self.send_header("Content-Type", content_type)
        if length is None:
            self.send_header("Connection", "close")
            self.close_connection = True
        else:
            self.send_header("Content-Length", str(length))
        self.end_headers()

    def _send_json(self, status: int, payload: Any, upstream_headers: Any = None) -> None:
        body = _dumps(payload)
        self._send_headers(status, upstream_headers or {}, "application/json", len(body))
        self.wfile.write(body)

    def _stream(self, engine: Engine, resp: Any, prelude: list[Any]) -> None:
        self._send_headers(resp.status, resp.headers, "text/event-stream", None)
        for msg in prelude:  # locally blocked calls from the same batch
            self.wfile.write(format_sse([("event", "message")], _dumps(msg).decode()))
        self.wfile.flush()
        for fields, data in iter_sse(iter(resp.readline, b"")):
            if data is not None:
                try:
                    parsed = json.loads(data)
                except ValueError:
                    pass
                else:
                    for out in engine.from_server(parsed).forward:
                        self.wfile.write(format_sse(fields, _dumps(out).decode()))
                    self.wfile.flush()
                    continue
            self.wfile.write(format_sse(fields, data))
            self.wfile.flush()

    def _relay(self, engine: Engine, resp: Any, prelude: list[Any], single: bool) -> None:
        ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        sid = resp.headers.get(SESSION_HEADER)
        if sid:
            self.proxy.adopt(engine, sid)
        if ctype == "text/event-stream":
            self._stream(engine, resp, prelude)
            return
        raw = resp.read()
        if ctype == "application/json" and raw:
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None
            if parsed is not None:
                forwarded = _flatten(engine.from_server(parsed).forward)
                merged = prelude + forwarded
                payload: Any = merged[0] if single and len(merged) == 1 else merged
                self._send_json(resp.status, payload, resp.headers)
                return
        if prelude and not raw:  # e.g. 202 for the notifications in a batch
            self._send_json(200, prelude[0] if single and len(prelude) == 1 else prelude, resp.headers)
            return
        self._send_headers(resp.status, resp.headers, resp.headers.get("Content-Type"), len(raw))
        self.wfile.write(raw)

    # ------------------------------------------------------------- methods

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        if not self._guard():
            return
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            msg = json.loads(body)
        except ValueError:
            self._reject(400, "body is not JSON")
            return
        sid = self.headers.get(SESSION_HEADER)
        is_init = isinstance(msg, dict) and msg.get("method") == "initialize"
        # A fresh initialize gets its own engine; it is adopted under the session id the server assigns.
        engine = (self.proxy._engine_factory(self.proxy.policy, self.proxy.store, server=self.proxy.name,
                                             session=self.proxy.session)
                  if is_init and not sid else self.proxy.engine(sid))
        verdict = engine.from_client(msg)
        replies = _flatten(verdict.reply)
        single = not isinstance(msg, list)
        if not verdict.forward:
            self._send_json(200, replies[0] if single and len(replies) == 1 else replies)
            return
        try:
            resp = self._upstream("POST", _dumps(verdict.forward[0]))
        except (urllib.error.URLError, OSError) as e:
            log.warning("upstream unreachable: %s", e)
            errors = [{"jsonrpc": "2.0", "id": i, "error": {"code": -32603, "message": f"sluice: upstream "
                       f"unreachable: {e}"}} for i in _ids(verdict.forward[0])]
            self._send_json(502, replies + errors if (replies or errors) else {"error": str(e)})
            return
        with resp:
            self._relay(engine, resp, replies, single)

    def do_GET(self) -> None:  # noqa: N802
        if not self._guard():
            return
        engine = self.proxy.engine(self.headers.get(SESSION_HEADER))
        try:
            resp = self._upstream("GET")
        except (urllib.error.URLError, OSError) as e:
            self._reject(502, f"upstream unreachable: {e}")
            return
        with resp:
            self._relay(engine, resp, [], single=True)

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._guard():
            return
        sid = self.headers.get(SESSION_HEADER)
        try:
            resp = self._upstream("DELETE")
        except (urllib.error.URLError, OSError) as e:
            self._reject(502, f"upstream unreachable: {e}")
            return
        with resp:
            raw = resp.read()
            self._send_headers(resp.status, resp.headers, resp.headers.get("Content-Type"), len(raw))
            self.wfile.write(raw)
        self.proxy.forget(sid)


def serve(proxy: HttpProxy, host: str = "127.0.0.1", port: int = 8931) -> None:
    server = proxy.make_server(host, port)
    log.warning("sluice: proxying %s at http://%s:%d%s", proxy.upstream, host, server.server_port, proxy.path)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
