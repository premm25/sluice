"""Action Sentinel: shadow mode records Sentinel's verdicts beside Sluice's; enforce mode lets Sentinel decide."""

import json
import threading

import pytest

from sluice import audit
from sluice.policy import PolicyError, from_dict
from sluice.sentinel import (
    SentinelClient,
    SentinelConfig,
    SentinelEnforcer,
    SentinelShadow,
    export,
    fit_arguments,
    make,
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
    assert from_dict({"sentinel": {"url": "http://x", "mode": "enforce"}}).sentinel.on_error == "block"
    with pytest.raises(PolicyError, match="mode"):
        from_dict({"sentinel": {"url": "http://x", "mode": "veto"}})
    with pytest.raises(PolicyError, match="on_error"):
        from_dict({"sentinel": {"url": "http://x", "mode": "enforce", "on_error": "ignore"}})
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
    assert "no Sentinel verdicts" in capsys.readouterr().out


# ------------------------------------------------------------------ enforce mode

class FakeSentinelService:
    """Sentinel's evaluate/begin/finish and review states, as config/sentinel-mcp.yaml behaves over the API."""

    def __init__(self, outcomes=None, down=False):
        self.outcomes = outcomes or {}
        self.down = down
        self.decisions: dict[str, dict] = {}   # event_id -> {status, codes, review}
        self.reviews: dict[str, str] = {}      # review_id -> state
        self.started: set[str] = set()
        self.finished: list[tuple[str, bool]] = []
        self.evaluated = 0

    def __call__(self, method, path, data, headers):
        if self.down:
            raise OSError("connection refused")
        body = json.loads(data) if data else {}
        if path == "/decisions/evaluate":
            self.evaluated += 1
            a = body["action"]
            d = self.decisions.get(a["event_id"])
            dup = d is not None
            if d is None:
                status, codes = self.outcomes.get(a["action_payload"]["tool"], ("APPROVE", []))
                d = {"status": status, "codes": codes, "review": None}
                if status == "HUMAN_REVIEW":
                    d["review"] = f"rev-{len(self.reviews) + 1}"
                    self.reviews[d["review"]] = "PENDING"
                self.decisions[a["event_id"]] = d
            state = self.reviews.get(d["review"]) if d["review"] else None
            token = (f"tok-{a['event_id']}" if (d["status"] == "APPROVE" and not dup) or state == "APPROVED"
                     else None)
            return 200, json.dumps({"decision": {"status": d["status"], "reason_codes": d["codes"]},
                                    "duplicate": dup, "review_id": d["review"], "review_state": state,
                                    "authorization_token": token}).encode()
        if path == "/executions/begin":
            event = body["token"].removeprefix("tok-")
            assert event == body["action"]["event_id"]  # the very proposal that was approved
            status = "DUPLICATE" if event in self.started else "STARTED"
            self.started.add(event)
            return 200, json.dumps({"execution_id": f"exe-{event}", "status": status, "reason_codes": []}).encode()
        if path.startswith("/executions/") and path.endswith("/finish"):
            self.finished.append((path.split("/")[2], body["ok"]))
            return 200, b'{"status": "EXECUTED"}'
        return 404, b'{"detail": "not found"}'


def enforcer(fake, **cfg):
    config = SentinelConfig(**{**CONFIG, "mode": "enforce", **cfg})
    return SentinelEnforcer(config, SentinelClient(config, transport=fake))


def enforced(store):
    return [e for e in audit.events(store) if e["event"] == "sentinel_enforce"]


def ok(text="ok"):
    return {"content": [{"type": "text", "text": text}], "isError": False}


def test_make_picks_the_worker_for_the_mode():
    assert type(make(SentinelConfig(**CONFIG))) is SentinelShadow
    assert type(make(SentinelConfig(**CONFIG, mode="enforce"))) is SentinelEnforcer


def test_enforce_runs_approved_calls_and_reports_how_they_ended(make_engine, store):
    fake = FakeSentinelService()
    sen = enforcer(fake)
    h = make_engine(sentinel=sen)
    assert h.call("list_files", {}) == (False, ok())
    assert h.call("read_file", {"path": "a"}, server_text="boom", is_error=True)[0] is False
    assert sen.flush()
    assert [good for _, good in fake.finished] == [True, False]  # the server's error is reported as a failed run
    assert all(e["detail"]["ran"] for e in enforced(store))


def test_enforce_blocks_what_sentinel_blocks(make_engine, store):
    fake = FakeSentinelService({"run_query": ("BLOCK", ["RULE_MCP_DESTRUCTIVE_SQL"])})
    h = make_engine(sentinel=enforcer(fake))
    blocked, result = h.call("run_query", {"sql": "DROP TABLE users"})
    assert blocked and "RULE_MCP_DESTRUCTIVE_SQL" in result["content"][0]["text"]
    assert fake.started == set()
    (e,) = enforced(store)
    assert e["decision"] == "block" and e["detail"]["sentinel"] == "BLOCK" and not e["detail"]["ran"]


def test_a_held_call_runs_once_after_a_person_approves_it(make_engine, store):
    fake = FakeSentinelService({"delete_file": ("HUMAN_REVIEW", [])})
    h = make_engine(sentinel=enforcer(fake))
    args = {"path": "/tmp/report.txt"}

    blocked, result = h.call("delete_file", args)
    text = result["content"][0]["text"]
    assert blocked and "rev-1" in text and "has NOT run" in text and "same arguments" in text

    assert h.call("delete_file", args)[0] is True                     # retried before anyone approved
    assert h.call("delete_file", {"path": "/tmp/other"})[0] is True   # different arguments: a new review
    assert fake.reviews == {"rev-1": "PENDING", "rev-2": "PENDING"}

    fake.reviews["rev-1"] = "APPROVED"
    assert h.call("delete_file", args) == (False, ok())               # the retry runs
    assert len(fake.started) == 1
    assert h.call("delete_file", args)[0] is True                     # ...once: calling again is a new review
    assert fake.reviews["rev-3"] == "PENDING"

    rows = enforced(store)
    assert [(e["detail"]["retry"], e["detail"]["ran"]) for e in rows] == [
        (False, False), (True, False), (False, False), (True, True), (False, False)]
    r = report(store)
    assert r["enforce"] == {"ran": 1, "held": 2, "stopped": 0} and r["recorded"] == 3  # retries count once


def test_a_rejected_call_is_stopped_and_forgotten(make_engine, store):
    fake = FakeSentinelService({"send_email": ("HUMAN_REVIEW", [])})
    h = make_engine(sentinel=enforcer(fake))
    h.call("send_email", {"to": "a@b.c"})
    fake.reviews["rev-1"] = "REJECTED"
    blocked, result = h.call("send_email", {"to": "a@b.c"})
    assert blocked and "rejected" in result["content"][0]["text"]
    h.call("send_email", {"to": "a@b.c"})
    assert fake.reviews["rev-2"] == "PENDING"  # asked again from scratch


def test_sluice_blocks_first_and_sentinel_only_records(make_engine, store):
    fake = FakeSentinel()
    config = SentinelConfig(**{**CONFIG, "mode": "enforce"})
    sen = SentinelEnforcer(config, SentinelClient(config, transport=fake))
    h = make_engine({"rules": [{"match": "wipe", "action": "deny"}]}, sentinel=sen)
    assert h.call("wipe", {})[0] is True
    assert sen.flush()
    assert [p for p, _, _ in fake.sent] == ["/decisions/assess"]  # assessed for the record, never evaluated
    assert verdicts(store)[0]["detail"]["sluice"] == "block"


def test_unreachable_sentinel_blocks_unless_the_policy_allows(make_engine, store):
    h = make_engine(sentinel=enforcer(FakeSentinelService(down=True)))
    blocked, result = h.call("list_files", {})
    assert blocked and "could not be asked" in result["content"][0]["text"]
    h2 = make_engine(sentinel=enforcer(FakeSentinelService(down=True), on_error="allow"))
    assert h2.call("list_files", {})[0] is False


def test_a_slow_sentinel_does_not_hold_the_engine_lock(make_engine, store):
    gate = threading.Event()
    fake = FakeSentinelService()

    def slow(method, path, data, headers):
        if path == "/decisions/evaluate":
            gate.wait(5)
        return fake(method, path, data, headers)

    config = SentinelConfig(**{**CONFIG, "mode": "enforce"})
    h = make_engine(sentinel=SentinelEnforcer(config, SentinelClient(config, transport=slow)))
    t = threading.Thread(target=h.call, args=("list_files", {}))
    t.start()
    try:
        assert h.engine._lock.acquire(timeout=2)  # free while the call waits for Sentinel
        h.engine._lock.release()
        assert h.list_tools([]) == []  # other requests still go through
    finally:
        gate.set()
        t.join(5)
    assert not t.is_alive()


def test_export_writes_one_row_per_call_ready_to_label(make_engine, store):
    fake = FakeSentinelService({"delete_file": ("HUMAN_REVIEW", [])})
    h = make_engine(sentinel=enforcer(fake))
    secret = {"path": "/tmp/a", "token": "ghp_" + "a" * 36, "api_key": "sk-live-123", "max_tokens": 5}
    h.call("list_files", {"dir": "/tmp"})
    h.call("delete_file", secret)
    fake.reviews["rev-1"] = "APPROVED"
    h.call("delete_file", secret)
    rows = export(store)
    assert [(r["tool"], r["sentinel"], r["review_state"], r["ran"], r["label"]) for r in rows] == [
        ("list_files", "APPROVE", None, True, None), ("delete_file", "HUMAN_REVIEW", "APPROVED", True, None)]
    assert "ghp_" not in json.dumps(rows) and "sk-live" not in json.dumps(rows)  # secrets are redacted
    assert rows[1]["arguments"]["max_tokens"] == 5 and rows[1]["arguments"]["path"] == "/tmp/a"
