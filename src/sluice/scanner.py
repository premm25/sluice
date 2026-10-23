"""Static scanning of MCP client configurations.

``sluice scan`` launches every stdio server in a Claude Desktop / Cursor /
VS Code config, lists its tools, and reports:

* tool poisoning findings per tool (injection, hidden Unicode, shadowing)
* capability labels per tool
* **toxic combinations**: whether the configuration *as a whole* contains a
  lethal trifecta (private source + untrusted source + sink), even when each
  server looks harmless on its own.

Output formats: text, json, and SARIF 2.1.0 (for GitHub code scanning).
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sluice import __version__
from sluice.client import StdioClient
from sluice.detectors import Finding, foreign_tool_names, max_severity, scan_tool, severity_rank
from sluice.flow import PRIVATE, SINK, UNTRUSTED
from sluice.policy import Policy

WRAPPED_MARKER = "sluice"


def default_config_paths() -> list[Path]:
    home = Path.home()
    candidates: list[Path] = []
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
    elif sys.platform == "darwin":
        candidates.append(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
    else:
        candidates.append(home / ".config" / "Claude" / "claude_desktop_config.json")
    candidates += [home / ".cursor" / "mcp.json", Path.cwd() / ".vscode" / "mcp.json",
                   Path.cwd() / ".mcp.json", home / ".claude.json"]
    return [p for p in candidates if p.exists()]


def load_servers(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        raise ValueError(f"{path}: 'mcpServers' must be an object")
    return servers


def unwrap_command(spec: dict[str, Any]) -> list[str] | None:
    """Return the real server command, looking through an existing sluice wrapper."""
    if "command" not in spec:
        return None
    cmd = [spec["command"], *spec.get("args", [])]
    if "--" in cmd and any(WRAPPED_MARKER in str(c) for c in cmd[: cmd.index("--")]):
        return cmd[cmd.index("--") + 1:]
    return cmd


@dataclass
class ToolReport:
    name: str
    labels: set[str]
    findings: list[Finding]


@dataclass
class ServerReport:
    name: str
    command: list[str] | None
    tools: list[ToolReport] = field(default_factory=list)
    error: str | None = None
    skipped: str | None = None
    definitions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ScanReport:
    servers: list[ServerReport]

    def trifecta(self) -> dict[str, list[str]]:
        legs: dict[str, list[str]] = {PRIVATE: [], UNTRUSTED: [], SINK: []}
        for s in self.servers:
            for t in s.tools:
                for label in t.labels:
                    legs[label].append(f"{s.name}/{t.name}")
        return legs

    @property
    def has_trifecta(self) -> bool:
        return all(self.trifecta().values())

    def worst(self) -> str | None:
        return max_severity(f for s in self.servers for t in s.tools for f in t.findings)


def scan_server(name: str, spec: dict[str, Any], policy: Policy, timeout: float = 20) -> ServerReport:
    cmd = unwrap_command(spec)
    report = ServerReport(name, cmd)
    if cmd is None:
        report.skipped = "remote (HTTP) server -- only stdio servers can be launched for scanning"
        return report
    try:
        with StdioClient(cmd, env=spec.get("env")) as client:
            client.initialize(timeout=timeout)
            tools = client.list_tools(timeout=timeout)
    except Exception as e:  # report and keep scanning other servers
        report.error = str(e).strip() or type(e).__name__
        return report
    report.definitions = tools
    return report


def scan(servers: dict[str, dict[str, Any]], policy: Policy, timeout: float = 20) -> ScanReport:
    reports = [scan_server(n, s, policy, timeout) for n, s in servers.items()]
    # Shadowing is judged across servers: a tool mentioning a *sibling* tool is normal.
    names = {r.name: {str(t.get("name", "")) for t in r.definitions} for r in reports}
    for r in reports:
        foreign = foreign_tool_names(set().union(*(v for k, v in names.items() if k != r.name)), names[r.name])
        for tool in r.definitions:
            tname = str(tool.get("name", ""))
            r.tools.append(ToolReport(tname, policy.labels_for(r.name, tname, tool), scan_tool(tool, foreign)))
    return ScanReport(reports)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def to_json(report: ScanReport) -> dict[str, Any]:
    return {
        "tool": "sluice", "version": __version__,
        "lethal_trifecta": report.has_trifecta,
        "trifecta_legs": report.trifecta(),
        "servers": [{
            "name": s.name, "command": s.command, "error": s.error, "skipped": s.skipped,
            "tools": [{"name": t.name, "labels": sorted(t.labels),
                       "findings": [f.to_dict() for f in t.findings]} for t in s.tools],
        } for s in report.servers],
    }


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(report: ScanReport, config_uri: str = "mcp.json") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for s in report.servers:
        for t in s.tools:
            for f in t.findings:
                rules.setdefault(f.code, {"id": f.code, "shortDescription": {"text": f.message}})
                results.append({
                    "ruleId": f.code, "level": _SARIF_LEVEL[f.severity],
                    "message": {"text": f"[{s.name}/{t.name}] {f.message}" + (f": {f.evidence}" if f.evidence else "")},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": config_uri}}}],
                })
    if report.has_trifecta:
        rules["lethal_trifecta"] = {"id": "lethal_trifecta",
                                    "shortDescription": {"text": "configuration enables the lethal trifecta"}}
        legs = report.trifecta()
        results.append({
            "ruleId": "lethal_trifecta", "level": "warning",
            "message": {"text": "private: {}; untrusted: {}; sink: {}".format(
                *(", ".join(legs[k][:5]) for k in (PRIVATE, UNTRUSTED, SINK)))},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": config_uri}}}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "sluice", "version": __version__,
                                      "informationUri": "https://github.com/premm25/sluice",
                                      "rules": list(rules.values())}},
                  "results": results}],
    }


_LABEL_COLOR = {PRIVATE: "blue", UNTRUSTED: "yellow", SINK: "magenta"}


def render_text(report: ScanReport) -> str:
    from sluice.term import sev, style
    lines: list[str] = []
    for s in report.servers:
        lines.append(style(f"■ {s.name}", "bold") + style(f"  {' '.join(s.command or [])}", "gray"))
        if s.skipped:
            lines.append(style(f"    skipped: {s.skipped}", "gray"))
            continue
        if s.error:
            lines.append(style(f"    error: {s.error}", "red"))
            continue
        for t in s.tools:
            labels = " ".join(style(f"[{lab}]", _LABEL_COLOR[lab]) for lab in sorted(t.labels))
            mark = style("✓", "green") if not t.findings else style("✗", "red")
            lines.append(f"    {mark} {t.name} {labels}")
            for f in sorted(t.findings, key=lambda f: -severity_rank(f.severity)):
                lines.append(f"        {sev(f.severity)} {f.code}: {f.message}")
                if f.evidence:
                    lines.append(style(f"          ↳ {f.evidence[:160]}", "gray"))
    lines.append("")
    legs = report.trifecta()
    if report.has_trifecta:
        lines.append(style("⚠ Lethal trifecta: this configuration lets a prompt injection exfiltrate private data.",
                           "bold", "red"))
        for label in (PRIVATE, UNTRUSTED, SINK):
            shown = ", ".join(legs[label][:6]) + (" …" if len(legs[label]) > 6 else "")
            lines.append(f"    {label:<9} {shown}")
        lines.append(style("    Run these servers behind `sluice run` (see `sluice wrap`) to enforce flow control.",
                           "gray"))
    else:
        missing = [k for k, v in legs.items() if not v]
        lines.append(style(f"✓ No lethal trifecta (missing: {', '.join(missing)}).", "green"))
    return "\n".join(lines)
