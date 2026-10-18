from __future__ import annotations

import itertools
from typing import Any

import pytest

from sluice.engine import Engine
from sluice.policy import Policy, from_dict
from sluice.store import Store


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SLUICE_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SLUICE_POLICY", raising=False)
    monkeypatch.delenv("SLUICE_SESSION", raising=False)


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "state.db")
    yield s
    s.close()


_ids = itertools.count(1)


def request(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": next(_ids), "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def response(req: dict[str, Any], result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req["id"], "result": result}


def text_result(text: str, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


class Harness:
    """Drive an Engine as if a client and server were attached."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def list_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        req = request("tools/list", {})
        v = self.engine.from_client(req)
        assert v.forward == [req]
        out = self.engine.from_server(response(req, {"tools": tools}))
        return out.forward[0]["result"]["tools"]

    def call(self, name: str, args: dict[str, Any], server_text: str = "ok", is_error: bool = False):
        """Returns (blocked: bool, result dict as seen by the client)."""
        req = request("tools/call", {"name": name, "arguments": args})
        v = self.engine.from_client(req)
        if v.reply:
            return True, v.reply[0]["result"]
        assert v.forward == [req]
        out = self.engine.from_server(response(req, text_result(server_text, is_error)))
        return False, out.forward[0]["result"]


@pytest.fixture
def make_engine(store):
    def factory(policy: Policy | dict[str, Any] | None = None, server: str = "srv",
                session: str = "s1", db: Store | None = None) -> Harness:
        if isinstance(policy, dict):
            policy = from_dict(policy)
        return Harness(Engine(policy or Policy(), db or store, server=server, session=session))
    return factory


def tool(name: str, description: str = "", **props: str) -> dict[str, Any]:
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": {k: {"type": "string", "description": v}
                                                             for k, v in props.items()}}}
