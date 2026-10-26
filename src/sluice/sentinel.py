"""Optional: ask an Action Sentinel service what it would decide about each tool call (shadow mode).

`Action Sentinel <https://github.com/premm25/action-sentinel>`_ decides whether an agent's action may run:
deterministic rules, an optional model risk judgement (VegaML), human review and one-time signed approvals.
Sluice and Sentinel look at different things -- Sluice at where data flows, Sentinel at what the action
does -- so running both catches more than either alone.

In **shadow** mode (the only mode so far) Sentinel never changes what Sluice does. After Sluice has decided
a ``tools/call``, the call is queued and a background thread sends it to Sentinel's
``POST /decisions/assess``, which stores no decision. Sentinel's verdict is written to Sluice's audit log
next to Sluice's own decision (event ``sentinel_shadow``), so ``sluice sentinel report`` can show how
often they agree before anyone lets Sentinel block anything. The proxy never waits for Sentinel: when the
queue is full, calls are dropped from the comparison and counted.

Each call is sent as Sentinel action type ``mcp_tool_call`` with payload ``{server, tool, arguments}`` and
target ``mcp/<server>/<tool>``; Sentinel's ``config/sentinel-mcp.yaml`` profile is written for that shape.
The arguments are sent as they are, because Sentinel's rules need to see them: point ``url`` only at a
Sentinel service you run. Standard library only.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sluice import __version__

log = logging.getLogger("sluice")

JSON = dict[str, Any]
MAX_ARGUMENT_BYTES = 48 * 1024  # Sentinel accepts payloads up to 64 KB and 10 levels deep
MAX_ARGUMENT_DEPTH = 8
_ID_BAD = re.compile(r"[^A-Za-z0-9._:\-]")

# (method, path, JSON body, headers) -> (HTTP status, response body); the tests swap this out.
Transport = Callable[[str, str, bytes | None, dict[str, str]], tuple[int, bytes]]


@dataclass
class SentinelConfig:
    url: str = ""                          # e.g. "http://127.0.0.1:8000"; empty = off
    api_key_env: str = "SENTINEL_API_KEY"  # environment variable holding the API key (never in the policy)
    agent_id: str = "mcp-proxy"            # the API key's principal id in Sentinel
    mode: str = "shadow"                   # shadow: record Sentinel's verdict, change nothing
    timeout: float = 30.0                  # seconds per request
    max_pending: int = 100                 # calls queued for Sentinel at once; more are dropped (and counted)

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def api_key(self) -> str | None:
        return os.environ.get(self.api_key_env) or None


@dataclass
class Verdict:
    """Sentinel's answer for one call. ``outcome`` is None when Sentinel couldn't be asked."""

    outcome: str | None                    # APPROVE | HUMAN_REVIEW | BLOCK | ABSTAIN | ERROR
    reason_codes: list[str] = field(default_factory=list)
    error: str | None = None
    latency_ms: float = 0.0


def _ident(value: str, prefix: str) -> str:
    """Sentinel ids allow [A-Za-z0-9._:-], up to 128 characters, starting with a letter or digit."""
    clean = _ID_BAD.sub("-", value)[:100]
    return clean if clean[:1].isalnum() else f"{prefix}{clean}"[:128]


def _depth(value: Any, level: int = 0) -> int:
    if isinstance(value, dict):
        return max([level + 1] + [_depth(v, level + 1) for v in value.values()])
    if isinstance(value, list):
        return max([level + 1] + [_depth(v, level + 1) for v in value])
    return level


def fit_arguments(args: Any) -> JSON:
    """The call's arguments, or a marked preview of them when they're too large or deep for Sentinel."""
    args = args if isinstance(args, dict) else {"value": args}
    text = json.dumps(args, ensure_ascii=False, default=str)
    if len(text.encode("utf-8")) <= MAX_ARGUMENT_BYTES and _depth(args) <= MAX_ARGUMENT_DEPTH:
        return json.loads(text)
    return {"_sluice_truncated": True, "_preview": text[:4000]}


def proposal(server: str, tool: str, args: Any, *, session: str, agent_id: str,
             sluice_decision: str, sluice_codes: list[str]) -> JSON:
    """The Sentinel ``ActionProposal`` for one tools/call."""
    event = f"sluice-{uuid.uuid4().hex}"
    return {
        "event_id": event, "task_id": _ident(session, "s-"), "agent_id": agent_id,
        "agent_version": f"sluice-{__version__}", "action_type": "mcp_tool_call",
        "action_payload": {"server": server, "tool": tool, "arguments": fit_arguments(args)},
        "target_resource": f"mcp/{server}/{tool}"[:512], "source_system": "mcp-proxy", "evidence_refs": [],
        "proposed_at": datetime.now(UTC).isoformat(),
        "context": {"proxy": "sluice", "session": session, "sluice_decision": sluice_decision,
                    "sluice_codes": sluice_codes},
        "idempotency_key": event,
    }


class SentinelClient:
    def __init__(self, config: SentinelConfig, transport: Transport | None = None):
        self.config = config
        self._transport = transport or self._urllib

    def health(self) -> JSON:
        return self._call("GET", "/health")

    def assess(self, action: JSON) -> Verdict:
        t0 = time.perf_counter()
        try:
            out = self._call("POST", "/decisions/assess", {"action": action})
            d = out.get("decision") or {}
            v = Verdict(d.get("status"), [str(c) for c in d.get("reason_codes") or []])
        except Exception as e:  # shadow mode records the failure; it never affects the call
            v = Verdict(None, error=f"{type(e).__name__}: {e}"[:500])
        v.latency_ms = round(1000 * (time.perf_counter() - t0), 1)
        return v

    def _call(self, method: str, path: str, body: JSON | None = None) -> JSON:
        key = self.config.api_key()
        if key is None and path != "/health":
            raise RuntimeError(f"environment variable {self.config.api_key_env} (the Sentinel API key) is not set")
        headers = {"Accept": "application/json", **({"X-API-Key": key} if key else {})}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, raw = self._transport(method, path, data, headers)
        try:
            out = json.loads(raw or b"{}")
        except ValueError:
            out = {"detail": raw[:300].decode("utf-8", "replace")}
        if status >= 400:
            detail = out.get("detail", out) if isinstance(out, dict) else out
            raise RuntimeError(f"Sentinel answered HTTP {status}: {str(detail)[:300]}")
        return out

    def _urllib(self, method: str, path: str, data: bytes | None, headers: dict[str, str]) -> tuple[int, bytes]:
        req = urllib.request.Request(self.config.url.rstrip("/") + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:  # the operator's own URL
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()


class SentinelShadow:
    """Sends calls to Sentinel from a background thread and records its verdicts in the audit log."""

    def __init__(self, config: SentinelConfig, client: SentinelClient | None = None):
        self.config = config
        self.client = client or SentinelClient(config)
        self.dropped = 0
        self._queue: queue.Queue[tuple[Any, ...]] = queue.Queue(maxsize=max(1, config.max_pending))
        self._worker = threading.Thread(target=self._run, name="sluice-sentinel", daemon=True)
        self._worker.start()

    def submit(self, audit: Any, server: str, session: str, tool: str, args: Any,
               decision: str, codes: list[str]) -> bool:
        """Queue one decided call. Never blocks; returns False when the call was dropped."""
        try:
            self._queue.put_nowait((audit, server, session, tool, args, decision, list(codes)))
            return True
        except queue.Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                log.warning("Sentinel is not keeping up: %d call(s) left out of the shadow comparison", self.dropped)
            return False

    def flush(self, timeout: float = 30.0) -> bool:
        """Wait until every queued call has been assessed and recorded (tests and shutdown)."""
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks:
            if time.monotonic() > deadline:
                return False
            time.sleep(0.01)
        return True

    def _run(self) -> None:
        while True:
            audit, server, session, tool, args, decision, codes = self._queue.get()
            try:
                action = proposal(server, tool, args, session=session, agent_id=self.config.agent_id,
                                  sluice_decision=decision, sluice_codes=codes)
                v = self.client.assess(action)
                note = (f"Sentinel: {v.outcome} ({', '.join(v.reason_codes) or 'no reason codes'})" if v.outcome
                        else f"Sentinel unavailable: {v.error}")
                audit.log("sentinel_shadow", tool=tool, decision="info", reason=f"{note}; sluice: {decision}",
                          sentinel=v.outcome, sentinel_codes=v.reason_codes, sentinel_error=v.error,
                          sluice=decision, sluice_codes=codes, latency_ms=v.latency_ms,
                          event_id=action["event_id"])
            except Exception:  # never let one bad call stop the worker
                log.exception("sentinel shadow: could not record a verdict")
            finally:
                self._queue.task_done()


# What each side would do with the call, for comparing them.
SLUICE_WOULD = {"allow": "run", "warn": "run", "block": "stop", "would_block": "stop"}
SENTINEL_WOULD = {"APPROVE": "run", "HUMAN_REVIEW": "hold", "BLOCK": "stop", "ABSTAIN": "hold", "ERROR": "hold"}


def report(store: Any) -> JSON:
    """Agreement between Sluice and Sentinel over the recorded shadow verdicts."""
    rows = store.query("SELECT server, tool, detail FROM audit WHERE event='sentinel_shadow' ORDER BY id")
    pairs: dict[str, int] = {}
    outcomes: dict[str, int] = {}
    disagreements: list[JSON] = []
    unavailable = 0
    for r in rows:
        d = json.loads(r["detail"])
        if d.get("sentinel") is None:
            unavailable += 1
            continue
        outcomes[d["sentinel"]] = outcomes.get(d["sentinel"], 0) + 1
        mine, theirs = SLUICE_WOULD.get(d.get("sluice"), "?"), SENTINEL_WOULD.get(d["sentinel"], "?")
        key = f"sluice {mine} / sentinel {theirs}"
        pairs[key] = pairs.get(key, 0) + 1
        if mine != theirs and len(disagreements) < 20:
            disagreements.append({"server": r["server"], "tool": r["tool"], "sluice": d.get("sluice"),
                                  "sentinel": d["sentinel"], "sentinel_codes": d.get("sentinel_codes", [])})
    assessed = sum(outcomes.values())
    agree = sum(n for k, n in pairs.items() if k in ("sluice run / sentinel run", "sluice stop / sentinel stop"))
    return {"recorded": len(rows), "assessed": assessed, "unavailable": unavailable,
            "sentinel_outcomes": outcomes, "pairs": dict(sorted(pairs.items())),
            "agreement": round(agree / assessed, 3) if assessed else None,
            "disagreements": disagreements}
