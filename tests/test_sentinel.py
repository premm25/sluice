"""Action Sentinel shadow mode: Sentinel's verdicts are recorded beside Sluice's and never change a decision."""

import json
import threading

import pytest

from sluice import audit
from sluice.policy import PolicyError, from_dict
from sluice.sentinel import (
    SentinelClient,
    SentinelConfig,
    SentinelShadow,
    fit_arguments,
    proposal,
    report,
)

CONFIG = {"url": "http://sentinel.test", "api_key_env": "TEST_SENTINEL_KEY"}


class FakeSentinel:
    """Answers POST /decisions/assess like Sentinel's MCP profile would, and remembers what it was sent."""

    def __init__(self, outcomes=None, status=200, gate: threading.Event | None = None):
        self.outcomes = outcomes or {}
        self.status = status
        self.gate = gate
        self.sent = []

    def __call__(self, method, path, data, headers):
        if self.gate is not None:
            self.gate.wait(5)
        if path == "/health":
            return 200, b'{"status": "ok", "version": "0.2.1", "environment": "dev", "policy_version": "gov"}'
        body = json.loads(data)
        self.sent.append((path, headers, body))
        if self.status != 200:
            return self.status, b'{"detail": "invalid API key"}'
        tool = body["action"]["action_payload"]["tool"]
        outcome, codes = self.outcomes.get(tool, ("APPROVE", []))
        return 200, json.dumps({"decision": {"status": outcome, "reason_codes": codes}}).encode()


def shadow(fake, **cfg):
    config = SentinelConfig(**{**CONFIG, **cfg})
    return SentinelShadow(config, SentinelClient(config, transport=fake))


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("TEST_SENTINEL_KEY", "dev-mcp-key")


def verdicts(store):
    return [e for e in audit.events(store) if e["event"] == "sentinel_shadow"]


# ------------------------------------------------------------------ policy

def test_policy_section_is_optional_and_validated():
    assert not from_dict({}).sentinel.enabled
    p = from_dict({"sentinel": {"url": "http://127.0.0.1:8000"}})
    assert p.sentinel.enabled and p.sentinel.mode == "shadow" and p.sentinel.agent_id == "mcp-proxy"
    with pytest.raises(PolicyError, match="mode"):
        from_dict({"sentinel": {"url": "http://x", "mode": "enforce"}})  # not available yet
    with pytest.raises(PolicyError, match="http"):
        from_dict({"sentinel": {"url": "ftp://x"}})
    with pytest.raises(PolicyError, match="api_key"):
        from_dict({"sentinel": {"url": "http://x", "api_key": "sk-in-the-file"}})  # keys come from the env


# ------------------------------------------------------------------ proposal

def test_proposal_has_the_shape_sentinel_expects():
    p = proposal("notes", "read_note", {"title": "x"}, session="client-42 (pid)", agent_id="mcp-proxy",
                 sluice_decision="allow", sluice_codes=[])
    assert p["action_type"] == "mcp_tool_call" and p["source_system"] == "mcp-proxy"
    assert p["action_payload"] == {"server": "notes", "tool": "read_note", "arguments": {"title": "x"}}
    assert p["target_resource"] == "mcp/notes/read_note" and p["task_id"] == "client-42--pid-"
    assert p["event_id"] == p["idempotency_key"] and p["proposed_at"].endswith("+00:00")


def test_oversized_or_deep_arguments_are_sent_as_a_marked_preview():
    assert fit_arguments({"a": 1}) == {"a": 1}
    big = fit_arguments({"text": "x" * 60_000})
    assert big["_sluice_truncated"] and len(big["_preview"]) == 4000
    deep: dict = {}
    node = deep
    for _ in range(12):
        node["n"] = {}
        node = node["n"]
    assert fit_arguments(deep)["_sluice_truncated"]


# ------------------------------------------------------------------ engine

def test_verdicts_are_recorded_and_never_change_sluices_decision(make_engine, store):
    fake = FakeSentinel({"delete_file": ("BLOCK", ["RULE_X"]), "list_files": ("APPROVE", [])})
    sh = shadow(fake)
    h = make_engine({"rules": [{"match": "rm_all", "action": "deny"}]}, server="files", sentinel=sh)
    assert h.call("list_files", {})[0] is False
    assert h.call("delete_file", {"path": "/tmp/a"})[0] is False   # Sentinel would block; shadow lets it run
    assert h.call("rm_all", {})[0] is True                          # Sluice blocks; Sentinel's view still recorded
    assert sh.flush()
    got = [(e["tool"], e["detail"]["sluice"], e["detail"]["sentinel"]) for e in verdicts(store)]
    assert got == [("list_files", "allow", "APPROVE"), ("delete_file", "allow", "BLOCK"), ("rm_all", "block", "APPROVE")]
    path, headers, body = fake.sent[1]
    assert path == "/decisions/assess" and headers["X-API-Key"] == "dev-mcp-key"
    assert body["action"]["action_payload"] == {"server": "files", "tool": "delete_file",
                                                "arguments": {"path": "/tmp/a"}}
    assert all(e["decision"] == "info" for e in verdicts(store))  # not counted as blocks
    assert audit.verify(store).ok


def test_sentinel_failures_are_recorded_and_harmless(make_engine, store, monkeypatch):
    sh = shadow(FakeSentinel(status=401))
    h = make_engine(sentinel=sh)
    assert h.call("list_files", {})[0] is False
    assert sh.flush()  # the worker reads the key when it sends, so let the first call go out first
    monkeypatch.delenv("TEST_SENTINEL_KEY")
    assert h.call("list_files", {})[0] is False
    assert sh.flush()
    first, second = verdicts(store)
    assert first["detail"]["sentinel"] is None and "401" in first["detail"]["sentinel_error"]
    assert "TEST_SENTINEL_KEY" in second["detail"]["sentinel_error"]


def test_the_proxy_never_waits_for_sentinel(make_engine, store):
    gate = threading.Event()  # Sentinel hangs until released
    sh = shadow(FakeSentinel(gate=gate), max_pending=2)
    h = make_engine(sentinel=sh)
    for _ in range(6):
        assert h.call("list_files", {})[0] is False  # returns at once although Sentinel is stuck
    assert sh.dropped >= 3
    gate.set()
    assert sh.flush()
    assert len(verdicts(store)) == 6 - sh.dropped


def test_report_compares_the_two(make_engine, store):
    sh = shadow(FakeSentinel({"send_email": ("HUMAN_REVIEW", []), "read_note": ("APPROVE", [])}))
    h = make_engine({"rules": [{"match": "wipe", "action": "deny"}]}, sentinel=sh)
    for name in ("read_note", "read_note", "send_email", "wipe"):
        h.call(name, {})
    assert sh.flush()
    r = report(store)
    assert r["assessed"] == 4 and r["agreement"] == 0.5
    assert r["pairs"] == {"sluice run / sentinel hold": 1, "sluice run / sentinel run": 2,
                          "sluice stop / sentinel run": 1}
    assert {d["tool"] for d in r["disagreements"]} == {"send_email", "wipe"}


def test_replay_style_engines_have_no_sentinel(make_engine, store):
    h = make_engine()
    h.call("list_files", {})
    assert h.engine.sentinel is None and verdicts(store) == []


# ------------------------------------------------------------------ CLI

def test_cli_check_and_report(tmp_path, monkeypatch, capsys):
    from sluice import cli
    policy = tmp_path / "policy.toml"
    policy.write_text('[sentinel]\nurl = "http://sentinel.test"\napi_key_env = "TEST_SENTINEL_KEY"\n',
                      encoding="utf-8")
    fake = FakeSentinel()
    real_init = SentinelClient.__init__
    monkeypatch.setattr(SentinelClient, "__init__", lambda self, config, transport=None:
                        real_init(self, config, transport=fake))
    assert cli.main(["sentinel", "--policy", str(policy), "check"]) == 0
    out = capsys.readouterr().out
    assert "Sentinel 0.2.1" in out and "assessed as APPROVE" in out
    assert cli.main(["sentinel", "--policy", str(policy), "report"]) == 0
    assert "no Sentinel shadow verdicts" in capsys.readouterr().out
