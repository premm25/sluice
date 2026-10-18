import tomllib

import pytest

from sluice.labels import auto_labels
from sluice.policy import DEFAULT_POLICY_TOML, PolicyError, from_dict, load
from sluice.ratelimit import RateLimiter, parse_rate


def codes(violations):
    return [v.code for v in violations]


def test_default_policy_template_is_valid():
    p = from_dict(tomllib.loads(DEFAULT_POLICY_TOML))
    assert p.mode == "enforce" and p.rules and p.tool_labels


def test_load_without_file_returns_defaults():
    p = load()
    assert p.source == "<defaults>" and p.enforce


def test_load_reads_env_var(tmp_path, monkeypatch):
    f = tmp_path / "p.toml"
    f.write_text('mode = "monitor"\n')
    monkeypatch.setenv("SLUICE_POLICY", str(f))
    assert load().mode == "monitor"


@pytest.mark.parametrize("data,needle", [
    ({"mood": "enforce"}, "unknown key"),
    ({"mode": "yolo"}, "mode must be one of"),
    ({"flow": {"exfiltration": "maybe"}}, "exfiltration"),
    ({"rules": [{"action": "deny"}]}, "'match' is required"),
    ({"rules": [{"match": "x", "rate_limit": "lots"}]}, "invalid rate limit"),
    ({"rules": [{"match": "x", "args": {"p": {"deny": ["("]}}}]}, "invalid regex"),
    ({"tools": [{"match": "x", "labels": ["secret"]}]}, "unknown label"),
    ({"flow": {"allow_flows": ["fs:* to github:*"]}}, "allow_flows"),
])
def test_validation_errors(data, needle):
    with pytest.raises(PolicyError, match=needle):
        from_dict(data)


def test_invalid_toml_reports_file(tmp_path):
    f = tmp_path / "bad.toml"
    f.write_text("mode = ")
    with pytest.raises(PolicyError, match="invalid TOML"):
        load(f)


def test_deny_rule_and_glob_matching():
    p = from_dict({"rules": [{"match": "*delete*", "action": "deny", "reason": "no deletes"}]})
    assert codes(p.evaluate("fs", "delete_file", {})) == ["rule_deny"]
    assert p.evaluate("fs", "read_file", {}) == []
    assert p.is_hidden("fs", "bulk_delete")


def test_server_scoped_rules():
    p = from_dict({"rules": [{"match": "github:create_*", "action": "deny"}]})
    assert p.evaluate("github", "create_issue", {})
    assert p.evaluate("gitlab", "create_issue", {}) == []


def test_default_deny_allowlist():
    p = from_dict({"default_action": "deny", "rules": [{"match": "read_*"}]})
    assert p.evaluate("s", "read_file", {}) == []
    assert codes(p.evaluate("s", "exec", {})) == ["default_deny"]


def test_arg_deny_patterns_and_wildcard():
    p = from_dict({"rules": [
        {"match": "run", "args": {"cmd": {"deny": [r"rm\s+-rf"], "max_length": 20}}},
        {"match": "*", "args": {"*": {"deny": ["169\\.254\\.169\\.254"]}}},
    ]})
    assert codes(p.evaluate("s", "run", {"cmd": "rm -rf /"})) == ["arg_denied"]
    assert codes(p.evaluate("s", "run", {"cmd": "echo " + "x" * 30})) == ["arg_too_long"]
    assert p.evaluate("s", "run", {"cmd": "ls"}) == []
    assert codes(p.evaluate("s", "fetch", {"opts": {"url": "http://169.254.169.254/latest"}})) == ["arg_denied"]


def test_arg_within_blocks_traversal(tmp_path):
    root = tmp_path / "work"
    root.mkdir()
    p = from_dict({"rules": [{"match": "read_file", "args": {"path": {"within": [str(root)]}}}]})
    assert p.evaluate("s", "read_file", {"path": str(root / "a.txt")}) == []
    assert codes(p.evaluate("s", "read_file", {"path": str(root / ".." / "secret.txt")})) == ["path_outside"]
    assert codes(p.evaluate("s", "read_file", {"path": "file://" + str(tmp_path / "x")})) == ["path_outside"]


def test_arg_one_of_allow_and_required():
    p = from_dict({"rules": [{"match": "t", "args": {
        "env": {"one_of": ["dev", "staging"]},
        "url": {"allow": ["^https://api\\.corp\\.example/"]},
        "ticket": {"required": True},
    }}]})
    ok = {"env": "dev", "url": "https://api.corp.example/v1", "ticket": "T-1"}
    assert p.evaluate("s", "t", ok) == []
    assert codes(p.evaluate("s", "t", {**ok, "env": "prod"})) == ["arg_not_allowed"]
    assert codes(p.evaluate("s", "t", {**ok, "url": "https://evil.example"})) == ["arg_not_allowed"]
    assert codes(p.evaluate("s", "t", {"env": "dev"})) == ["arg_required"]


def test_rate_limit_rule():
    p = from_dict({"rules": [{"match": "send", "rate_limit": "2/minute"}]})
    rl = RateLimiter()
    assert p.evaluate("s", "send", {}, rl) == []
    assert p.evaluate("s", "send", {}, rl) == []
    assert codes(p.evaluate("s", "send", {}, rl)) == ["rate_limit"]


def test_token_bucket_refills():
    rl = RateLimiter()
    assert rl.allow("k", 1, 10, now=0)
    assert not rl.allow("k", 1, 10, now=5)
    assert rl.allow("k", 1, 10, now=15.1)


@pytest.mark.parametrize("spec,expected", [("10/minute", (10, 60.0)), ("5/s", (5, 1.0)), ("100 / hours", (100, 3600.0))])
def test_parse_rate(spec, expected):
    assert parse_rate(spec) == expected


def test_explicit_labels_override_auto():
    p = from_dict({"tools": [{"match": "fetch", "labels": ["untrusted"]}]})
    assert p.labels_for("s", "fetch") == {"untrusted"}
    assert "sink" in auto_labels("fetch")


@pytest.mark.parametrize("name,props,expected", [
    ("read_file", ["path"], {"private"}),
    ("fetch", ["url"], {"untrusted", "sink"}),
    ("send_email", ["to", "body"], {"sink"}),
    ("create_issue", ["title", "body"], {"sink"}),
    ("search_web", ["query"], {"untrusted"}),
    ("get_weather", ["city"], set()),
    ("list_emails", [], {"private", "untrusted"}),
    ("postMessage", ["channel", "text"], {"sink"}),
    ("query_database", ["sql"], {"private"}),
])
def test_auto_labels(name, props, expected):
    tool = {"inputSchema": {"properties": {p: {} for p in props}}}
    assert auto_labels(name, tool) == expected
