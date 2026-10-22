"""Streamable HTTP transport: `sluice serve` in front of a remote MCP server."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from sluice.demo.http_server import DemoHttpServer
from sluice.http_proxy import HttpProxy, format_sse, iter_sse
from sluice.policy import Policy, from_dict


def start_proxy(upstream_url, store, policy=None, **kwargs):
    proxy = HttpProxy(upstream_url, policy or Policy(), store, name="remote", session="http-test", **kwargs)
    server = proxy.make_server("127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return proxy, server, f"http://127.0.0.1:{server.server_port}/mcp"


@pytest.fixture
def upstream(request):
    sse = getattr(request, "param", False)
    srv = DemoHttpServer("weather", sse=sse).start()
    yield srv
    srv.stop()


@pytest.fixture
def proxied(upstream, store):
    proxy, server, url = start_proxy(upstream.url, store)
    yield url
    server.shutdown()
    server.server_close()


def send(url, msg, headers=None, method="POST"):
    """Returns (status, headers, list_of_jsonrpc_messages)."""
    data = json.dumps(msg).encode() if msg is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream", **(headers or {})})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as e:
        resp = e
    with resp:
        body = resp.read()
        ctype = (resp.headers.get("Content-Type") or "").split(";")[0]
        if ctype == "text/event-stream":
            msgs = [json.loads(d) for _, d in iter_sse(iter(body.splitlines(keepends=True))) if d]
        elif body:
            parsed = json.loads(body)
            msgs = parsed if isinstance(parsed, list) else [parsed]
        else:
            msgs = []
        return resp.status, resp.headers, msgs


def init(url):
    status, headers, [reply] = send(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                          "params": {"protocolVersion": "2025-06-18", "capabilities": {}}})
    assert status == 200 and "result" in reply
    return {"Mcp-Session-Id": headers["Mcp-Session-Id"]}


@pytest.mark.parametrize("upstream", [False, True], indirect=True, ids=["json", "sse"])
def test_tools_list_is_inspected_over_http(upstream, proxied):
    sid = init(proxied)
    status, _, [reply] = send(proxied, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
    assert status == 200
    names = [t["name"] for t in reply["result"]["tools"]]
    assert names == ["get_forecast"]  # the poisoned get_weather is quarantined


@pytest.mark.parametrize("upstream", [False, True], indirect=True, ids=["json", "sse"])
def test_tool_calls_pass_through_over_http(upstream, proxied):
    sid = init(proxied)
    send(proxied, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
    _, _, [reply] = send(proxied, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                   "params": {"name": "get_forecast", "arguments": {"city": "Oslo"}}}, sid)
    assert "Oslo" in reply["result"]["content"][0]["text"]


def test_blocked_call_is_answered_locally_and_never_reaches_upstream(upstream, store):
    policy = from_dict({"rules": [{"match": "get_forecast", "args": {"city": {"one_of": ["Oslo"]}}}]})
    _, server, url = start_proxy(upstream.url, store, policy)
    try:
        sid = init(url)
        _, _, [reply] = send(url, {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                   "params": {"name": "get_forecast", "arguments": {"city": "Paris"}}}, sid)
        assert reply["id"] == 7 and reply["result"]["isError"]
        assert "must be one of" in reply["result"]["content"][0]["text"]
        assert not any(m.get("method") == "tools/call" for m in upstream.received)
    finally:
        server.shutdown()
        server.server_close()


def test_mixed_batch_merges_local_blocks_with_upstream_replies(upstream, store):
    policy = from_dict({"rules": [{"match": "get_weather", "action": "deny"}]})
    _, server, url = start_proxy(upstream.url, store, policy)
    try:
        sid = init(url)
        batch = [
            {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "get_forecast", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "get_weather", "arguments": {}}},
        ]
        _, _, replies = send(url, batch, sid)
        by_id = {r["id"]: r for r in replies}
        assert set(by_id) == {10, 11}
        assert by_id[11]["result"]["isError"] and not by_id[10]["result"]["isError"]
    finally:
        server.shutdown()
        server.server_close()


def test_notifications_get_202(proxied):
    sid = init(proxied)
    status, _, msgs = send(proxied, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    assert status == 202 and msgs == []


@pytest.mark.parametrize("origin,allowed", [
    ("http://localhost:3000", True), ("http://127.0.0.1", True),
    ("https://evil.example", False), ("http://localhost.evil.example", False),
])
def test_origin_validation_blocks_dns_rebinding(proxied, origin, allowed):
    status, _, _ = send(proxied, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"Origin": origin})
    assert (status != 403) is allowed


def test_allow_origin_option(upstream, store):
    _, server, url = start_proxy(upstream.url, store, allow_origins=("https://app.example",))
    try:
        assert send(url, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"Origin": "https://app.example"})[0] == 200
    finally:
        server.shutdown()
        server.server_close()


def test_wrong_path_is_404(proxied):
    assert send(proxied.replace("/mcp", "/other"), {"jsonrpc": "2.0", "id": 1, "method": "ping"})[0] == 404


def test_upstream_errors_are_relayed(proxied):
    status, _, _ = send(proxied, None, method="GET")
    assert status == 405  # the demo upstream doesn't offer a GET stream
    assert send(proxied, None, init(proxied), method="DELETE")[0] == 200


def test_unreachable_upstream_returns_jsonrpc_error(store):
    _, server, url = start_proxy("http://127.0.0.1:9/mcp", store)
    try:
        status, _, [reply] = send(url, {"jsonrpc": "2.0", "id": 5, "method": "ping"})
        assert status == 502 and reply["id"] == 5 and "unreachable" in reply["error"]["message"]
    finally:
        server.shutdown()
        server.server_close()


def test_extra_headers_are_sent_upstream(store):
    seen = {}

    class Capture(DemoHttpServer):
        pass
    srv = Capture("weather").start()
    original = srv.server.RequestHandlerClass.do_POST

    def do_post(handler):
        seen.update(handler.headers.items())
        original(handler)
    srv.server.RequestHandlerClass.do_POST = do_post
    _, server, url = start_proxy(srv.url, store, extra_headers={"Authorization": "Bearer t0ken"})
    try:
        send(url, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"Origin": "http://localhost"})
        assert seen.get("Authorization") == "Bearer t0ken"
        assert "Origin" not in seen  # the browser origin is not forwarded upstream
    finally:
        server.shutdown()
        server.server_close()
        srv.stop()


def test_sse_parsing_roundtrip():
    raw = (b": comment\n\nevent: message\nid: 4\ndata: {\"a\":\ndata: 1}\n\n"
           b"data: plain\n\n")
    events = list(iter_sse(iter(raw.splitlines(keepends=True))))
    assert events == [([("event", "message"), ("id", "4")], '{"a":\n1}'), ([], "plain")]
    again = b"".join(format_sse(f, d) for f, d in events)
    assert list(iter_sse(iter(again.splitlines(keepends=True)))) == events
