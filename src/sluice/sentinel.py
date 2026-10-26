"""Optional: ask an Action Sentinel service about each tool call, in shadow or enforce mode.

`Action Sentinel <https://github.com/premm25/action-sentinel>`_ decides whether an agent's action may run:
deterministic rules, an optional model risk judgement (VegaML), human review and one-time signed approvals.
Sluice and Sentinel look at different things -- Sluice at where data flows, Sentinel at what the action
does -- so running both catches more than either alone.

**shadow** (default): Sentinel never changes what Sluice does. After Sluice has decided a ``tools/call``, the
call is queued and a background thread sends it to Sentinel's ``POST /decisions/assess``, which stores no
decision. The proxy never waits for Sentinel: when the queue is full, calls are dropped from the comparison
and counted.

**enforce**: a call Sluice lets through is also sent to ``POST /decisions/evaluate`` before it reaches the
server, and runs only with Sentinel's one-time authorization (``/executions/begin``, then ``/finish`` when the
server answers). A BLOCK stops it. A HUMAN_REVIEW holds it: the agent is told the call is waiting for a
person, and when it calls the tool again with exactly the same arguments after a reviewer approved it, the
same proposal is resubmitted, Sentinel hands back the reviewer's authorization, and the call runs once. If
Sentinel can't be reached the call is blocked (``on_error = "block"``) unless the policy says ``"allow"``.
Held calls are kept in memory: after Sluice restarts, a retry is a new proposal and needs a new review.

Either way Sentinel's verdict is written to Sluice's audit log next to Sluice's own decision (events
``sentinel_shadow`` and ``sentinel_enforce``) with the call's arguments, secrets redacted. ``sluice sentinel
report`` compares the two; ``sluice sentinel export`` writes the calls out for labelling, to fit VegaML on.

Each call is sent as Sentinel action type ``mcp_tool_call`` with payload ``{server, tool, arguments}`` and
target ``mcp/<server>/<tool>``; Sentinel's ``config/sentinel-mcp.yaml`` profile is written for that shape.
The arguments are sent as they are, because Sentinel's rules need to see them: point ``url`` only at a
Sentinel service you run. Standard library only.
"""

from __future__ import annotations

import hashlib
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
from sluice.recording import redact_tree

log = logging.getLogger("sluice")

JSON = dict[str, Any]
MAX_ARGUMENT_BYTES = 48 * 1024  # Sentinel accepts payloads up to 64 KB and 10 levels deep
MAX_ARGUMENT_DEPTH = 8
_ID_BAD = re.compile(r"[^A-Za-z0-9._:\-]")
_SECRET_NAME = re.compile(r"(?i)(passw|secret|token|api[_-]?key|apikey|authorization|bearer|credential|private[_-]?key|cookie)")

# (method, path, JSON body, headers) -> (HTTP status, response body); the tests swap this out.
Transport = Callable[[str, str, bytes | None, dict[str, str]], tuple[int, bytes]]


@dataclass
class SentinelConfig:
    url: str = ""                          # e.g. "http://127.0.0.1:8000"; empty = off
    api_key_env: str = "SENTINEL_API_KEY"  # environment variable holding the API key (never in the policy)
    agent_id: str = "mcp-proxy"            # the API key's principal id in Sentinel
    mode: str = "shadow"                   # shadow: record Sentinel's verdict | enforce: Sentinel decides too
    on_error: str = "block"                # enforce, Sentinel unreachable or failing: block | allow
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


def redact_arguments(node: Any) -> Any:
    """Arguments as kept in the audit log and exports: secret-looking values, and any value under a
    secret-sounding name (api_key, password, token, ...), are redacted."""
    if isinstance(node, dict):
        return {k: "[REDACTED]" if _SECRET_NAME.search(str(k)) and isinstance(v, str) and v else redact_arguments(v)
                for k, v in node.items()}
    if isinstance(node, list):
        return [redact_arguments(v) for v in node]
    return redact_tree(node)


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


def call_key(session: str, server: str, tool: str, args: Any) -> str:
    """Identifies "the same call again" for a held call: same session, server, tool and arguments."""
    text = json.dumps([session, server, tool, args], sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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

    def evaluate(self, action: JSON) -> JSON:
        """A stored decision (enforce mode): its review id and state, and a token when it may run."""
        return self._call("POST", "/decisions/evaluate", {"action": action})

    def begin(self, token: str, action: JSON) -> JSON:
        return self._call("POST", "/executions/begin", {"token": token, "action": action, "adapter": "sluice"})

    def finish(self, execution_id: str, ok: bool) -> JSON:
        return self._call("POST", f"/executions/{execution_id}/finish", {"ok": ok, "output": {}})

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


class _Background:
    """One worker thread and a bounded queue of jobs. ``put`` never blocks; a full queue drops (and counts)."""

    def __init__(self, max_pending: int):
        self.dropped = 0
        self._queue: queue.Queue[Callable[[], None]] = queue.Queue(maxsize=max(1, max_pending))
        self._worker = threading.Thread(target=self._run, name="sluice-sentinel", daemon=True)
        self._worker.start()

    def put(self, job: Callable[[], None]) -> bool:
        try:
            self._queue.put_nowait(job)
            return True
        except queue.Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                log.warning("Sentinel is not keeping up: %d request(s) dropped", self.dropped)
            return False

    def flush(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks:
            if time.monotonic() > deadline:
                return False
            time.sleep(0.01)
        return True

    def _run(self) -> None:
        while True:
            job = self._queue.get()
            try:
                job()
            except Exception:  # never let one bad job stop the worker
                log.exception("sentinel: background request failed")
            finally:
                self._queue.task_done()


class SentinelShadow:
    """Sends calls to Sentinel from a background thread and records its verdicts in the audit log."""

    enforcing = False

    def __init__(self, config: SentinelConfig, client: SentinelClient | None = None):
        self.config = config
        self.client = client or SentinelClient(config)
        self._background = _Background(config.max_pending)

    @property
    def dropped(self) -> int:
        return self._background.dropped

    def submit(self, audit: Any, server: str, session: str, tool: str, args: Any,
               decision: str, codes: list[str]) -> bool:
        """Queue one decided call for assessment. Never blocks; returns False when the call was dropped."""
        codes = list(codes)
        return self._background.put(lambda: self._assess(audit, server, session, tool, args, decision, codes))

    def flush(self, timeout: float = 30.0) -> bool:
        """Wait until every queued request has been sent and recorded (tests and shutdown)."""
        return self._background.flush(timeout)

    def _assess(self, audit: Any, server: str, session: str, tool: str, args: Any,
                decision: str, codes: list[str]) -> None:
        action = proposal(server, tool, args, session=session, agent_id=self.config.agent_id,
                          sluice_decision=decision, sluice_codes=codes)
        v = self.client.assess(action)
        note = (f"Sentinel: {v.outcome} ({', '.join(v.reason_codes) or 'no reason codes'})" if v.outcome
                else f"Sentinel unavailable: {v.error}")
        audit.log("sentinel_shadow", tool=tool, decision="info", reason=f"{note}; sluice: {decision}",
                  sentinel=v.outcome, sentinel_codes=v.reason_codes, sentinel_error=v.error,
                  sluice=decision, sluice_codes=codes, latency_ms=v.latency_ms,
                  event_id=action["event_id"], args=redact_arguments(action["action_payload"]["arguments"]))


@dataclass
class Gate:
    """Sentinel's answer for a call in enforce mode."""

    allowed: bool
    message: str = ""                  # why not, for the agent; for a held call, the review id
    held: bool = False                 # waiting for a person (as opposed to stopped)
    execution_id: str | None = None    # report the outcome here once the server answers


@dataclass
class _Held:
    action: JSON
    review_id: str


CLOSED_REVIEW = {"REJECTED": "a reviewer rejected it", "EXPIRED": "the review expired before anyone decided",
                 "CANCELLED": "the review was cancelled",
                 "OVERRIDDEN": "a reviewer approved a changed version of it, which Sluice does not run for you"}


class SentinelEnforcer(SentinelShadow):
    """Enforce mode: a call runs only with Sentinel's authorization. See the module docstring."""

    enforcing = True
    MAX_HELD = 1000

    def __init__(self, config: SentinelConfig, client: SentinelClient | None = None):
        super().__init__(config, client)
        self._held: dict[str, _Held] = {}
        self._lock = threading.Lock()

    def gate(self, audit: Any, server: str, session: str, tool: str, args: Any,
             decision: str, codes: list[str]) -> Gate:
        """Ask Sentinel before forwarding a call Sluice allowed. Waits for one or two requests."""
        key = call_key(session, server, tool, args)
        with self._lock:
            held = self._held.get(key)
        action = held.action if held else proposal(server, tool, args, session=session,
                                                   agent_id=self.config.agent_id, sluice_decision=decision,
                                                   sluice_codes=list(codes))
        t0 = time.perf_counter()
        status, rcodes, error = None, [], None
        review_id, review_state = (held.review_id if held else None), None
        try:
            out = self.client.evaluate(action)
            d = out.get("decision") or {}
            status, rcodes = d.get("status"), [str(c) for c in d.get("reason_codes") or []]
            review_id, review_state = out.get("review_id") or review_id, out.get("review_state")
            gate = self._decide(key, action, status, rcodes, review_id, review_state, out.get("authorization_token"))
        except Exception as e:
            error = f"{type(e).__name__}: {e}"[:500]
            gate = Gate(True) if self.config.on_error == "allow" else Gate(
                False, f"Action Sentinel could not be asked ({error}), and the policy blocks calls until it can")
        note = (f"Sentinel: {status} ({', '.join(rcodes) or 'no reason codes'})" if status
                else f"Sentinel unavailable: {error}")
        audit.log("sentinel_enforce", tool=tool, decision="info" if gate.allowed else "block",
                  reason=f"{note}; {'runs' if gate.allowed else 'held' if gate.held else 'stopped'}",
                  sentinel=status, sentinel_codes=rcodes, sentinel_error=error, sluice=decision,
                  sluice_codes=list(codes), review_id=review_id, review_state=review_state,
                  retry=held is not None, ran=gate.allowed, execution_id=gate.execution_id,
                  latency_ms=round(1000 * (time.perf_counter() - t0), 1), event_id=action["event_id"],
                  args=redact_arguments(action["action_payload"]["arguments"]))
        return gate

    def _decide(self, key: str, action: JSON, status: str | None, codes: list[str], review_id: str | None,
                review_state: str | None, token: str | None) -> Gate:
        if token:
            self._forget(key)
            ex = self.client.begin(token, action)
            if ex.get("status") == "STARTED":
                return Gate(True, execution_id=ex.get("execution_id"))
            return Gate(False, f"Action Sentinel did not let it run ({ex.get('status')}: "
                               f"{', '.join(ex.get('reason_codes') or []) or 'already run, or not authorized'})")
        if status == "HUMAN_REVIEW" and review_state in (None, "PENDING") and review_id:
            with self._lock:
                if key not in self._held and len(self._held) >= self.MAX_HELD:
                    self._held.pop(next(iter(self._held)))  # the oldest
                self._held.setdefault(key, _Held(action, review_id))
            return Gate(False, review_id, held=True)
        self._forget(key)
        if review_state in CLOSED_REVIEW:
            return Gate(False, f"Action Sentinel review {review_id}: {CLOSED_REVIEW[review_state]}")
        return Gate(False, f"Action Sentinel decided {status} ({', '.join(codes) or 'no reason given'})")

    def _forget(self, key: str) -> None:
        with self._lock:
            self._held.pop(key, None)

    def finish(self, audit: Any, tool: str, execution_id: str, ok: bool) -> None:
        """Report the server's answer for a call Sentinel let run (in the background)."""
        def job() -> None:
            try:
                self.client.finish(execution_id, ok)
            except Exception as e:
                audit.log("sentinel_finish_failed", tool=tool, decision="info", execution_id=execution_id,
                          error=f"{type(e).__name__}: {e}"[:500])
        if not self._background.put(job):
            audit.log("sentinel_finish_failed", tool=tool, decision="info", execution_id=execution_id,
                      error="queue full")


def make(config: SentinelConfig, client: SentinelClient | None = None) -> SentinelShadow:
    """The Sentinel worker for the policy's mode."""
    return (SentinelEnforcer if config.mode == "enforce" else SentinelShadow)(config, client)


# What each side would do with the call, for comparing them.
SLUICE_WOULD = {"allow": "run", "warn": "run", "block": "stop", "would_block": "stop"}
SENTINEL_WOULD = {"APPROVE": "run", "HUMAN_REVIEW": "hold", "BLOCK": "stop", "ABSTAIN": "hold", "ERROR": "hold"}


VERDICT_EVENTS = "('sentinel_shadow', 'sentinel_enforce')"


def report(store: Any) -> JSON:
    """Agreement between Sluice and Sentinel over the recorded verdicts (a retried held call counts once)."""
    rows = store.query(f"SELECT event, server, tool, detail FROM audit WHERE event IN {VERDICT_EVENTS} ORDER BY id")
    pairs: dict[str, int] = {}
    outcomes: dict[str, int] = {}
    disagreements: list[JSON] = []
    unavailable = recorded = 0
    final: dict[str, str] = {}  # enforce mode: event -> how the call ended (a retry can turn held into ran)
    for r in rows:
        d = json.loads(r["detail"])
        if r["event"] == "sentinel_enforce":
            closed = d.get("review_state") in CLOSED_REVIEW
            final[d.get("event_id")] = ("ran" if d.get("ran") else "held" if d.get("sentinel") == "HUMAN_REVIEW"
                                        and not closed else "stopped")
        if d.get("retry"):
            continue
        recorded += 1
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
    return {"recorded": recorded, "assessed": assessed, "unavailable": unavailable,
            "sentinel_outcomes": outcomes, "pairs": dict(sorted(pairs.items())),
            "agreement": round(agree / assessed, 3) if assessed else None,
            "enforce": {k: list(final.values()).count(k) for k in ("ran", "held", "stopped")} if final else None,
            "disagreements": disagreements}


def export(store: Any, since: float = 0.0) -> list[JSON]:
    """One row per call Sentinel saw, for labelling (fill in ``label``: safe, needs_review or unsafe).

    Arguments are as recorded, with secrets redacted. A held call's row shows how its review ended. Feed the
    labelled file to ``action-sentinel vega dataset`` to make a VegaML training/evaluation set.
    """
    rows = store.query(f"SELECT ts, session, server, event, tool, detail FROM audit WHERE event IN {VERDICT_EVENTS} "
                       "AND ts >= ? ORDER BY id", (since,))
    out: dict[str, JSON] = {}
    for r in rows:
        d = json.loads(r["detail"])
        if "args" not in d:  # recorded before arguments were kept
            continue
        eid = d.get("event_id") or f"row-{len(out)}"
        prev = out.get(eid)
        out[eid] = {
            "event_id": eid, "ts": prev["ts"] if prev else round(r["ts"], 3), "session": r["session"],
            "server": r["server"], "tool": r["tool"], "arguments": d["args"],
            "mode": "enforce" if r["event"] == "sentinel_enforce" else "shadow",
            "sluice": d.get("sluice"), "sluice_codes": d.get("sluice_codes", []),
            "sentinel": d.get("sentinel"), "sentinel_codes": d.get("sentinel_codes", []),
            "review_id": d.get("review_id"), "review_state": d.get("review_state"),
            "ran": bool(d.get("ran")) or bool(prev and prev["ran"]),
            "label": None,
        }
    return list(out.values())
