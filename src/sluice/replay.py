"""``sluice replay``: test a policy change against recorded traffic before deploying it.

Recorded sessions are fed, in their original order and with their original
timestamps, through fresh :class:`~sluice.engine.Engine` instances running the
candidate policy against a throwaway store. Every tool call is decided again
and compared with what actually happened:

* **newly blocked**: the change would break something that used to work
* **newly allowed**: the change loosens something that used to be stopped

Flow decisions are faithful: recorded result fingerprints are re-ingested, so
a replayed sink call is checked against exactly the private data that the
live session had seen. If the candidate policy blocks a call that originally
succeeded, its recorded result is *not* ingested -- that data would never
have arrived -- so downstream decisions change the way they really would.
"""

from __future__ import annotations

import copy
import logging
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sluice.engine import Engine
from sluice.policy import Policy
from sluice.recording import Event
from sluice.store import Store


def effective(decision: str) -> str:
    """Collapse decisions to what the policy *intended*: monitor-mode would_block counts as block."""
    return "block" if decision in ("block", "would_block") else "allow"


@dataclass
class Change:
    event: Event
    before: str
    after: str
    codes: list[str]
    reasons: list[str]


@dataclass
class ReplayReport:
    calls: int = 0
    sessions: set[str] = field(default_factory=set)
    first: float | None = None
    last: float | None = None
    changes: list[Change] = field(default_factory=list)
    unknown_results: int = 0  # newly allowed calls whose output was never recorded
    notes: list[str] = field(default_factory=list)

    @property
    def newly_blocked(self) -> list[Change]:
        return [c for c in self.changes if c.after == "block"]

    @property
    def newly_allowed(self) -> list[Change]:
        return [c for c in self.changes if c.after == "allow"]

    def to_json(self) -> dict[str, Any]:
        return {
            "calls": self.calls, "sessions": len(self.sessions), "first": self.first, "last": self.last,
            "newly_blocked": len(self.newly_blocked), "newly_allowed": len(self.newly_allowed),
            "unknown_results": self.unknown_results, "notes": self.notes,
            "changes": [{
                "id": c.event.id, "ts": c.event.ts, "session": c.event.session, "server": c.event.server,
                "tool": c.event.tool, "args": c.event.args, "before": c.before, "after": c.after,
                "codes": c.codes, "reasons": c.reasons,
            } for c in self.changes],
        }


def replay(policy: Policy, events: Iterable[Event], *, as_enforced: bool = True) -> ReplayReport:
    events = list(events)
    policy = copy.deepcopy(policy)
    report = ReplayReport()
    if as_enforced and policy.mode != "enforce":
        policy.mode = "enforce"
        report.notes.append("candidate policy is in monitor mode; replayed as if enforced")
    recorded_k = next(((e.data.get("k"), e.data.get("w")) for e in events if e.kind in ("result", "resource")
                       and e.data.get("k")), None)
    if recorded_k and recorded_k != (policy.flow.kgram, policy.flow.window):
        policy.flow.kgram, policy.flow.window = recorded_k
        report.notes.append(f"using recorded fingerprint parameters k={recorded_k[0]} w={recorded_k[1]}")

    logger = logging.getLogger("sluice")
    was_disabled, logger.disabled = logger.disabled, True  # replayed decisions are reported, not logged
    with tempfile.TemporaryDirectory(prefix="sluice-replay-", ignore_cleanup_errors=True) as tmp:
        store = Store(Path(tmp) / "replay.db")
        now = [0.0]
        engines: dict[tuple[str, str], Engine] = {}
        blocked_now: set[int] = set()
        try:
            for ev in events:
                now[0] = ev.ts
                key = (ev.session, ev.server)
                engine = engines.get(key)
                if engine is None:
                    engine = engines[key] = Engine(policy, store, server=ev.server, session=ev.session,
                                                   clock=lambda: now[0], record=False)
                if ev.kind == "list":
                    engine.observe_tools(ev.data.get("tools", []))
                elif ev.kind == "call":
                    report.calls += 1
                    report.sessions.add(ev.session)
                    report.first = ev.ts if report.first is None else report.first
                    report.last = ev.ts
                    d = engine.decide_call(ev.tool or "", ev.args)
                    before, after = effective(ev.decision), "block" if d.blocked else "allow"
                    if d.blocked:
                        blocked_now.add(ev.id)
                    if before != after:
                        report.changes.append(Change(ev, before, after, d.codes, d.reasons))
                        if after == "allow" and ev.decision == "block":
                            report.unknown_results += 1
                elif ev.kind == "result":
                    if ev.ref in blocked_now:
                        continue  # the candidate policy stops this call, so its output never arrives
                    engine.ingest_result(ev.tool or "", ev.fingerprints, set(ev.data.get("tokens", [])),
                                         bool(ev.data.get("is_error")))
                elif ev.kind == "resource":
                    engine.ingest_result("resources/read", ev.fingerprints, set(ev.data.get("tokens", [])),
                                         resource=True)
        finally:
            store.close()
            logger.disabled = was_disabled
    return report


def render_text(report: ReplayReport, policy_source: str, show: int = 20) -> str:
    import datetime as dt

    from sluice.term import style

    def when(ts: float | None) -> str:
        return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "-"

    def args_preview(args: dict[str, Any]) -> str:
        import json
        text = json.dumps(args, ensure_ascii=False)
        return text if len(text) <= 70 else text[:70] + "…"

    lines = [style(f"Replayed {report.calls} recorded call(s) from {len(report.sessions)} session(s) "
                   f"({when(report.first)} → {when(report.last)}) against {policy_source}", "bold")]
    for note in report.notes:
        lines.append(style(f"  note: {note}", "gray"))
    if not report.calls:
        lines.append(style("  nothing recorded yet: run your MCP servers behind `sluice run` first", "yellow"))
        return "\n".join(lines)

    for title, changes, mark, color in (("newly BLOCKED", report.newly_blocked, "✗", "red"),
                                        ("newly ALLOWED", report.newly_allowed, "↑", "yellow")):
        if not changes:
            continue
        lines.append(style(f"  {mark} {len(changes)} call(s) {title}", "bold", color))
        for c in changes[:show]:
            e = c.event
            lines.append(f"      {when(e.ts)}  {e.server}/{e.tool}  " + style(args_preview(e.args), "gray"))
            if c.reasons:
                lines.append(style(f"        ↳ {'; '.join(c.reasons)[:160]}", "gray"))
        if len(changes) > show:
            lines.append(style(f"      … and {len(changes) - show} more (use --format json for all)", "gray"))
    unchanged = report.calls - len(report.changes)
    lines.append(style(f"  = {unchanged} call(s) unchanged", "green"))
    if report.unknown_results:
        lines.append(style(f"  note: {report.unknown_results} newly allowed call(s) were blocked when recorded, so "
                           "their results are unknown and later decisions may differ in reality", "gray"))
    return "\n".join(lines)
