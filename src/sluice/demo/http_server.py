"""Toy Streamable HTTP MCP server (stdlib) for tests and local experiments.

    python -m sluice.demo.http_server weather 9100          # JSON responses
    python -m sluice.demo.http_server weather 9100 --sse    # event-stream responses
"""

from __future__ import annotations

import json
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from sluice.demo.server import make_handler


class DemoHttpServer:
    def __init__(self, profile: str, port: int = 0, sse: bool = False):
        self.handle = make_handler(profile)
        self.sse = sse
        self.received: list[Any] = []  # every JSON-RPC message that reached this server
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, status: int, body: bytes = b"", ctype: str | None = None,
                      headers: dict[str, str] | None = None) -> None:
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                if ctype:
                    self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802
                msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                msgs = msg if isinstance(msg, list) else [msg]
                outer.received.extend(msgs)
                replies = [r for r in (outer.handle(m) for m in msgs if isinstance(m, dict)) if r is not None]
                headers = {}
                if any(isinstance(m, dict) and m.get("method") == "initialize" for m in msgs):
                    headers["Mcp-Session-Id"] = uuid.uuid4().hex
                if not replies:
                    self._send(202, headers=headers)
                elif outer.sse:
                    body = b"".join(b"event: message\nid: %d\ndata: %s\n\n" % (i, json.dumps(r).encode())
                                    for i, r in enumerate(replies))
                    self._send(200, b": keep-alive\n\n" + body, "text/event-stream", headers)
                else:
                    payload = replies if isinstance(msg, list) else replies[0]
                    self._send(200, json.dumps(payload).encode(), "application/json", headers)

            def do_GET(self) -> None:  # noqa: N802
                self._send(405, b"", headers={"Allow": "POST, DELETE"})

            def do_DELETE(self) -> None:  # noqa: N802
                self._send(200)

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/mcp"

    def start(self) -> DemoHttpServer:
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


if __name__ == "__main__":
    profile = sys.argv[1] if len(sys.argv) > 1 else "weather"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9100
    srv = DemoHttpServer(profile, port, sse="--sse" in sys.argv)
    print(f"demo MCP server '{profile}' at {srv.url}", flush=True)
    srv.server.serve_forever()
