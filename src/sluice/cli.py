"""Command-line interface."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import shutil
import sys
from pathlib import Path
from typing import Any

from sluice import __version__


def _strip_dashdash(cmd: list[str]) -> list[str]:
    return cmd[1:] if cmd and cmd[0] == "--" else cmd


def _load_policy(path: str | None):
    from sluice.policy import PolicyError, load
    try:
        return load(path)
    except PolicyError as e:
        print(f"sluice: policy error: {e}", file=sys.stderr)
        raise SystemExit(2) from None


def _store():
    from sluice.store import Store
    return Store()


# ---------------------------------------------------------------- commands

def cmd_run(a: argparse.Namespace) -> int:
    from sluice.engine import Engine
    from sluice.proxy import run_proxy

    cmd = _strip_dashdash(a.cmd)
    if not cmd:
        print("usage: sluice run [options] -- <server command...>", file=sys.stderr)
        return 2
    level = logging.ERROR if a.quiet else getattr(logging, a.log_level.upper())
    logging.basicConfig(stream=sys.stderr, level=level, format="[sluice] %(message)s")
    policy = _load_policy(a.policy)
    if a.monitor:
        policy.mode = "monitor"
    store = _store()
    store.gc(policy.flow.session_ttl * 2)
    name = a.name or Path(cmd[-1]).stem or "server"
    engine = Engine(policy, store, server=name)
    logging.getLogger("sluice").info("protecting '%s' (%s mode, policy %s, session %s)",
                                     name, policy.mode, policy.source, engine.session)
    try:
        return run_proxy(cmd, engine)
    except FileNotFoundError as e:
        print(f"sluice: cannot start server: {e}", file=sys.stderr)
        return 127


def cmd_scan(a: argparse.Namespace) -> int:
    from sluice.detectors import severity_rank
    from sluice.scanner import default_config_paths, load_servers, render_text, scan, to_json, to_sarif

    policy = _load_policy(a.policy)
    cmd = _strip_dashdash(a.cmd)
    servers: dict[str, dict[str, Any]] = {}
    config_uri = "mcp.json"
    if cmd:
        servers["server"] = {"command": cmd[0], "args": cmd[1:]}
    else:
        paths = [Path(p) for p in a.config] or default_config_paths()
        if not paths:
            print("sluice: no MCP config found. Pass a path (e.g. claude_desktop_config.json) "
                  "or a server command after --.", file=sys.stderr)
            return 2
        config_uri = paths[0].name
        for p in paths:
            try:
                for name, spec in load_servers(p).items():
                    servers[name if name not in servers else f"{p.stem}:{name}"] = spec
            except (OSError, ValueError) as e:
                print(f"sluice: cannot read {p}: {e}", file=sys.stderr)
                return 2
            if a.format == "text":
                print(f"scanning {p}", file=sys.stderr)

    report = scan(servers, policy, timeout=a.timeout)
    if a.format == "json":
        text = json.dumps(to_json(report), indent=2)
    elif a.format == "sarif":
        text = json.dumps(to_sarif(report, config_uri), indent=2)
    else:
        text = render_text(report)
    if a.output:
        Path(a.output).write_text(text, encoding="utf-8")
    else:
        print(text)

    worst = report.worst()
    if a.fail_on != "never" and worst and severity_rank(worst) >= severity_rank(a.fail_on):
        return 1
    if a.fail_on != "never" and report.has_trifecta and a.fail_on_trifecta:
        return 1
    return 0


def cmd_wrap(a: argparse.Namespace, unwrap: bool = False) -> int:
    from sluice.scanner import WRAPPED_MARKER, unwrap_command

    path = Path(a.config)
    data = json.loads(path.read_text(encoding="utf-8"))
    key = "mcpServers" if "mcpServers" in data else "servers"
    servers = data.get(key, {})
    changed = []
    for name, spec in servers.items():
        if "command" not in spec:
            continue
        args = spec.get("args", [])
        wrapped = "--" in args and any(WRAPPED_MARKER in str(x) for x in [spec["command"], *args[: args.index("--")]])
        if unwrap and wrapped:
            real = unwrap_command(spec) or []
            spec["command"], spec["args"] = real[0], real[1:]
            changed.append(name)
        elif not unwrap and not wrapped:
            policy = ["--policy", str(Path(a.policy).expanduser().resolve())] if a.policy else []
            spec["args"] = ["-m", "sluice", "run", "--name", name, *policy, "--", spec["command"], *args]
            spec["command"] = sys.executable
            changed.append(name)
    text = json.dumps(data, indent=2) + "\n"
    verb = "unwrapped" if unwrap else "wrapped"
    if a.in_place:
        if changed:
            backup = path.with_suffix(path.suffix + f".bak-{dt.datetime.now():%Y%m%d%H%M%S}")
            shutil.copy2(path, backup)
            path.write_text(text, encoding="utf-8")
            print(f"{verb} {len(changed)} server(s): {', '.join(changed)}  (backup: {backup})", file=sys.stderr)
            if not unwrap:
                print("restart your MCP client to apply.", file=sys.stderr)
        else:
            print(f"nothing to do: no servers to {'unwrap' if unwrap else 'wrap'}", file=sys.stderr)
    else:
        sys.stdout.write(text)
        print(f"# {verb} {len(changed)} server(s); re-run with --in-place to write {path}", file=sys.stderr)
    return 0


def cmd_init(a: argparse.Namespace) -> int:
    from sluice.policy import DEFAULT_POLICY_TOML
    from sluice.store import sluice_home

    path = Path(a.path) if a.path else sluice_home() / "policy.toml"
    if path.exists() and not a.force:
        print(f"sluice: {path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DEFAULT_POLICY_TOML, encoding="utf-8")
    print(f"wrote {path}")
    return 0


def cmd_policy_check(a: argparse.Namespace) -> int:
    p = _load_policy(a.path)
    print(f"ok: {p.source}  mode={p.mode} default_action={p.default_action} "
          f"rules={len(p.rules)} labelled_tools={len(p.tool_labels)}")
    if a.tool:
        server, _, tool = a.tool.rpartition(":")
        server = server or "default"
        print(f"  {server}:{tool} labels={sorted(p.labels_for(server, tool)) or '-'}"
              f" hidden={p.is_hidden(server, tool)}")
        args = json.loads(a.args) if a.args else {}
        for v in p.evaluate(server, tool, args):
            print(f"  violation {v.code}: {v.message}")
    return 0


def cmd_audit(a: argparse.Namespace) -> int:
    from sluice import audit
    from sluice.term import decision, style

    store = _store()
    if a.audit_cmd == "verify":
        v = audit.verify(store)
        if v.ok:
            print(style(f"audit chain intact: {v.checked} entries verified", "green"))
            return 0
        print(style(f"audit chain BROKEN at entry {v.broken_at}: {v.reason} ({v.checked} verified before it)",
                    "red"))
        return 1
    if a.audit_cmd == "stats":
        print(json.dumps(audit.stats(store), indent=2))
        return 0
    if a.audit_cmd == "report":
        from sluice.report import render
        out = Path(a.output)
        out.write_text(render(store, limit=a.limit), encoding="utf-8")
        print(f"wrote {out.resolve()}")
        return 0
    rows = audit.events(store, limit=a.n)
    if a.json:
        for e in rows:
            print(json.dumps(e, ensure_ascii=False))
        return 0
    for e in rows:
        t = dt.datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")
        d = e["detail"]
        note = "; ".join(d.get("reasons", [])) or d.get("reason", "") or ", ".join(
            f["code"] for f in d.get("findings", [])) or ", ".join(d.get("changed", []))
        print(f"{style(t, 'gray')} {decision(e['decision'])} {e['server']}/{e['tool'] or '-'} "
              f"{style(e['event'], 'bold')} {note}")
    return 0


def cmd_pins(a: argparse.Namespace) -> int:
    from sluice.pinning import PinStore
    pins = PinStore(_store())
    if a.pins_cmd == "approve":
        n = pins.approve(a.server, a.tool)
        print(f"approved {n} changed tool definition(s)")
        return 0
    if a.pins_cmd == "reset":
        n = pins.reset(a.server)
        print(f"removed {n} pin(s)")
        return 0
    rows = pins.list(a.server)
    if not rows:
        print("no pinned tools yet")
    for r in rows:
        flag = "CHANGED (pending approval)" if r["status"] == "changed" else "trusted"
        print(f"{r['server']:<16} {r['tool']:<32} {r['hash'][:12]}  {flag}")
    return 0


def cmd_session(a: argparse.Namespace) -> int:
    store = _store()
    if a.session_cmd == "clear":
        if a.session:
            store.clear_session(a.session)
            print(f"cleared taint for session {a.session}")
        else:
            for table in ("fingerprints", "tokens", "taint"):
                store.execute(f"DELETE FROM {table}")
            print("cleared taint for all sessions")
        return 0
    rows = store.query(
        "SELECT session, label, COUNT(DISTINCT tool) tools, MAX(ts) last FROM taint "
        "GROUP BY session, label ORDER BY last DESC")
    if not rows:
        print("no tainted sessions")
    for r in rows:
        last = dt.datetime.fromtimestamp(r["last"]).strftime("%Y-%m-%d %H:%M")
        print(f"{r['session']:<24} {r['label']:<10} {r['tools']} tool(s)  last {last}")
    return 0


def cmd_demo(a: argparse.Namespace) -> int:
    from sluice.demo.run import main as demo_main
    return demo_main(pace=0.0 if a.fast else 0.4)


# ------------------------------------------------------------------ parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sluice",
        description="Information-flow control for AI agents: an MCP proxy that stops "
                    "prompt-injection-driven data exfiltration.")
    p.add_argument("--version", action="version", version=f"sluice {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run an MCP server behind sluice (use in your MCP client config)")
    r.add_argument("--policy", help="policy TOML (default: $SLUICE_POLICY or ~/.sluice/policy.toml)")
    r.add_argument("--name", help="server name used in policies and logs")
    r.add_argument("--monitor", action="store_true", help="log what would be blocked, change nothing")
    r.add_argument("--quiet", action="store_true", help="only log errors")
    r.add_argument("--log-level", default="warning", choices=["debug", "info", "warning", "error"])
    r.add_argument("cmd", nargs=argparse.REMAINDER, help="-- server command and arguments")
    r.set_defaults(fn=cmd_run)

    s = sub.add_parser("scan", help="scan MCP configs for poisoned tools and toxic capability combinations")
    s.add_argument("config", nargs="*", help="config files (default: auto-detect Claude Desktop/Cursor/VS Code)")
    s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("-o", "--output", help="write report to a file")
    s.add_argument("--policy", help="policy TOML used for labels")
    s.add_argument("--timeout", type=float, default=20)
    s.add_argument("--fail-on", default="high", choices=["never", "low", "medium", "high", "critical"],
                   help="exit 1 if a finding is at least this severe (default: high)")
    s.add_argument("--fail-on-trifecta", action="store_true", help="exit 1 if the config has a lethal trifecta")
    s.add_argument("--cmd", nargs=argparse.REMAINDER, default=[], help="scan a single server command instead")
    s.set_defaults(fn=cmd_scan)

    for name, unwrap in (("wrap", False), ("unwrap", True)):
        w = sub.add_parser(name, help=("route every server in a config through sluice" if not unwrap
                                       else "remove sluice from a config"))
        w.add_argument("config")
        w.add_argument("--in-place", action="store_true", help="rewrite the file (a timestamped backup is kept)")
        if not unwrap:
            w.add_argument("--policy", help="policy file to pin in the wrapped commands")
        w.set_defaults(fn=lambda a, u=unwrap: cmd_wrap(a, unwrap=u), policy=None)

    i = sub.add_parser("init", help="write a documented starter policy")
    i.add_argument("path", nargs="?")
    i.add_argument("--force", action="store_true")
    i.set_defaults(fn=cmd_init)

    pc = sub.add_parser("policy", help="validate a policy and dry-run decisions")
    pcs = pc.add_subparsers(dest="policy_cmd", required=True)
    chk = pcs.add_parser("check")
    chk.add_argument("path", nargs="?")
    chk.add_argument("--tool", help="dry-run a tool, e.g. 'filesystem:read_file'")
    chk.add_argument("--args", help="JSON arguments for --tool")
    chk.set_defaults(fn=cmd_policy_check)

    au = sub.add_parser("audit", help="inspect the tamper-evident audit log")
    aus = au.add_subparsers(dest="audit_cmd", required=True)
    t = aus.add_parser("tail")
    t.add_argument("-n", type=int, default=30)
    t.add_argument("--json", action="store_true")
    aus.add_parser("verify")
    aus.add_parser("stats")
    rep = aus.add_parser("report", help="write a self-contained HTML report")
    rep.add_argument("-o", "--output", default="sluice-report.html")
    rep.add_argument("--limit", type=int, default=500)
    au.set_defaults(fn=cmd_audit)

    pn = sub.add_parser("pins", help="manage pinned tool definitions (rug-pull protection)")
    pns = pn.add_subparsers(dest="pins_cmd", required=True)
    pl = pns.add_parser("list")
    pl.add_argument("server", nargs="?")
    pa = pns.add_parser("approve", help="accept changed tool definitions")
    pa.add_argument("server", nargs="?")
    pa.add_argument("tool", nargs="?")
    pr = pns.add_parser("reset")
    pr.add_argument("server", nargs="?")
    pn.set_defaults(fn=cmd_pins)

    se = sub.add_parser("session", help="inspect or clear taint state")
    ses = se.add_subparsers(dest="session_cmd", required=True)
    ses.add_parser("list")
    sc = ses.add_parser("clear")
    sc.add_argument("session", nargs="?")
    se.set_defaults(fn=cmd_session)

    d = sub.add_parser("demo", help="watch sluice stop a prompt-injection exfiltration attack")
    d.add_argument("--fast", action="store_true")
    d.set_defaults(fn=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
    args = build_parser().parse_args(argv)
    return int(args.fn(args) or 0)
