"""The decision engine: transport-agnostic MCP message inspection.

:class:`Engine` sees every JSON-RPC message in both directions and returns a
:class:`Verdict` -- which messages to pass on and which replies to send back
to the sender. It performs no I/O of its own beyond the shared store, which
keeps it easy to test and to put behind any transport (stdio today).

Client -> server
    ``tools/call``   policy rules, quarantine, rate limits, and flow checks
                     on sink tools (trifecta + fingerprint exfiltration).
Server -> client
    ``tools/list``   poisoning scan, pinning (rug pulls), hiding denied tools,
                     hidden-Unicode sanitising, capability labelling.
    ``tools/call``   hidden-Unicode stripping, injection scan, taint recording
                     and fingerprinting, secret redaction.
    ``resources/read`` treated as a private source (configurable).
"""

from __future__ import annotations

import copy
import json
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sluice.audit import AuditLog
from sluice.detectors import (
    Finding,
    at_least,
    find_hidden,
    redact_secrets,
    scan_injection,
    scan_tool,
    strip_hidden,
)
from sluice.flow import PRIVATE, SINK, UNTRUSTED, FlowTracker
from sluice.pinning import PinStore
from sluice.policy import Policy
from sluice.ratelimit import RateLimiter
from sluice.store import Store, default_session

log = logging.getLogger("sluice")

JSON = dict[str, Any]


@dataclass
class Verdict:
    forward: list[Any] = field(default_factory=list)  # continue to the other side
    reply: list[Any] = field(default_factory=list)    # send straight back to the sender


@dataclass
class ToolInfo:
    labels: set[str]
    quarantine: str | None = None
    findings: list[Finding] = field(default_factory=list)


def _key(msg_id: Any) -> str:
    return json.dumps(msg_id, sort_keys=True)


def blocked_result(msg_id: Any, tool: str, reasons: list[str]) -> JSON:
    text = (f"[sluice] The call to '{tool}' was blocked by the user's security policy: "
            + "; ".join(reasons)
            + ". Do not retry this action or try to work around this block; tell the user what happened.")
    return {"jsonrpc": "2.0", "id": msg_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": True}}


def _map_texts(result: JSON, fn: Callable[[str], str]) -> JSON:
    """Apply ``fn`` to every text the model will read in a tool/resource result."""
    def walk(node: Any) -> Any:
        if isinstance(node, str):
            return fn(node)
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        return node

    out = dict(result)
    for key in ("content", "contents"):
        if isinstance(out.get(key), list):
            items = []
            for item in out[key]:
                if not isinstance(item, dict):
                    items.append(item)
                    continue
                item = dict(item)
                if isinstance(item.get("text"), str):
                    item["text"] = fn(item["text"])
                if isinstance(item.get("resource"), dict) and isinstance(item["resource"].get("text"), str):
                    item["resource"] = {**item["resource"], "text": fn(item["resource"]["text"])}
                items.append(item)
            out[key] = items
    if "structuredContent" in out:
        out["structuredContent"] = walk(out["structuredContent"])
    return out


def _collect_texts(result: JSON) -> str:
    parts: list[str] = []
    _map_texts(result, lambda s: parts.append(s) or s)
    return "\n".join(parts)


class Engine:
    def __init__(self, policy: Policy, store: Store, server: str = "default",
                 session: str | None = None):
        self.policy = policy
        self.store = store
        self.server = server
        self.session = session or default_session()
        self.audit = AuditLog(store, self.session, server)
        self.flow = FlowTracker(store, self.session, policy.flow.session_ttl,
                                policy.flow.kgram, policy.flow.window)
        self.pins = PinStore(store)
        self.limiter = RateLimiter()
        self.tools: dict[str, ToolInfo] = {}
        self._pending: dict[str, tuple[str, str | None]] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ API

    def from_client(self, msg: Any) -> Verdict:
        with self._lock:
            if isinstance(msg, list):
                return self._batch(msg, self._client_one)
            return self._client_one(msg)

    def from_server(self, msg: Any) -> Verdict:
        with self._lock:
            if isinstance(msg, list):
                return self._batch(msg, self._server_one)
            return self._server_one(msg)

    def labels(self, tool: str) -> set[str]:
        info = self.tools.get(tool)
        if info is not None:
            return info.labels
        return self.policy.labels_for(self.server, tool)

    # ------------------------------------------------------------- dispatch

    @staticmethod
    def _batch(msgs: list[Any], one: Callable[[Any], Verdict]) -> Verdict:
        fwd: list[Any] = []
        rep: list[Any] = []
        for m in msgs:
            v = one(m)
            fwd.extend(v.forward)
            rep.extend(v.reply)
        return Verdict([fwd] if fwd else [], [rep] if rep else [])

    def _client_one(self, msg: Any) -> Verdict:
        if not isinstance(msg, dict):
            return Verdict([msg])
        method = msg.get("method")
        if method is None or "id" not in msg:
            return Verdict([msg])  # notification or a response to a server->client request
        if method == "tools/call":
            return self._on_call(msg)
        self._pending[_key(msg["id"])] = (method, None)
        return Verdict([msg])

    def _server_one(self, msg: Any) -> Verdict:
        if not isinstance(msg, dict) or "method" in msg or "id" not in msg:
            if isinstance(msg, dict) and msg.get("method") == "notifications/tools/list_changed":
                self.audit.log("tools_changed_notice", decision="info")
            return Verdict([msg])
        entry = self._pending.pop(_key(msg["id"]), None)
        if entry is None or "result" not in msg:
            return Verdict([msg])
        method, tool = entry
        try:
            if method == "tools/list":
                msg = self._on_tools_list(msg)
            elif method == "tools/call":
                msg = self._on_call_result(msg, tool or "")
            elif method == "resources/read" and self.policy.flow.resources_private:
                msg = self._on_resource(msg)
        except Exception as e:  # fail closed: never pass an uninspected result through
            log.exception("inspection failed for %s", method)
            self.audit.log("engine_error", tool=tool, decision="block", method=method, error=repr(e))
            msg = {"jsonrpc": "2.0", "id": msg["id"],
                   "error": {"code": -32603, "message": f"sluice: failed to inspect {method} result"}}
        return Verdict([msg])

    # ------------------------------------------------------------ tools/call

    def _on_call(self, msg: JSON) -> Verdict:
        params = msg.get("params") or {}
        name = str(params.get("name", ""))
        args = params.get("arguments") or {}
        enforce = self.policy.enforce
        blocks: list[tuple[str, str]] = []
        warns: list[tuple[str, str]] = []

        info = self.tools.get(name)
        if info and info.quarantine:
            blocks.append(("quarantined", info.quarantine))
        for v in self.policy.evaluate(self.server, name, args, self.limiter):
            blocks.append((v.code, v.message))

        labels = self.labels(name)
        flow_detail: dict[str, Any] = {}
        if SINK in labels and self.policy.flow.enabled:
            if self.policy.flow.exfiltration != "off":
                leak = self.flow.check_sink(args)
                flow_detail["fingerprint_matches"] = leak.fingerprint_matches
                flow_detail["token_matches"] = leak.token_matches
                declassified = {s for s in leak.sources if self.policy.flow.flow_allowed(s, (self.server, name))}
                if declassified:
                    flow_detail["declassified"] = sorted(f"{s}/{t}" for s, t in declassified)
                if leak.leaked(self.policy.flow.min_matches) and leak.sources - declassified:
                    leak.sources -= declassified
                    target = blocks if self.policy.flow.exfiltration == "block" else warns
                    target.append(("exfiltration", leak.describe()))
            if self.policy.flow.trifecta != "off":
                taint = self.flow.taint()
                if taint.trifecta:
                    src = lambda xs: ", ".join(sorted({f"{s}/{t}" for s, t in xs}))  # noqa: E731
                    target = blocks if self.policy.flow.trifecta == "block" else warns
                    target.append(("lethal_trifecta",
                                   f"session holds private data ({src(taint.private)}) and untrusted content "
                                   f"({src(taint.untrusted)}); '{name}' can send data out"))

        detail = {"labels": sorted(labels), **flow_detail}
        for code, message in warns:
            log.warning("[%s] warn %s: %s", self.server, name, message)
            self.audit.log("call", tool=name, decision="warn", code=code, reason=message, **detail)

        if blocks:
            reasons = [m for _, m in blocks]
            codes = [c for c, _ in blocks]
            if enforce:
                log.warning("[%s] BLOCKED %s: %s", self.server, name, "; ".join(reasons))
                self.audit.log("call", tool=name, decision="block", codes=codes, reasons=reasons,
                               args=_preview(args), **detail)
                return Verdict(reply=[blocked_result(msg.get("id"), name, reasons)])
            self.audit.log("call", tool=name, decision="would_block", codes=codes, reasons=reasons,
                           args=_preview(args), **detail)
        elif not warns:
            self.audit.log("call", tool=name, decision="allow", **detail)

        self._pending[_key(msg["id"])] = ("tools/call", name)
        return Verdict([msg])

    def _on_call_result(self, msg: JSON, tool: str) -> JSON:
        result = msg["result"]
        if not isinstance(result, dict):
            return msg
        labels = self.labels(tool)
        enforce = self.policy.enforce
        det = self.policy.detect
        findings: list[Finding] = []

        text = _collect_texts(result)
        if det.strip_hidden_unicode:
            hidden = find_hidden(text)
            if hidden:
                findings.extend(hidden)
                if enforce:
                    result = _map_texts(result, strip_hidden)
                text = strip_hidden(text)

        if self.policy.flow.enabled and not result.get("isError"):
            if PRIVATE in labels and text:
                n = self.flow.record_private(self.server, tool, text)
                log.debug("[%s] fingerprinted %d features from %s", self.server, n, tool)
            if UNTRUSTED in labels:
                self.flow.record_untrusted(self.server, tool)

        decision = "allow"
        if det.output_injection != "off":
            inj = [f for f in scan_injection(text) if f.code not in ("hidden_unicode", "hidden_payload")]
            if inj:
                findings.extend(inj)
                if det.output_injection == "block" and at_least(inj, "high"):
                    decision = "block" if enforce else "would_block"
                    if enforce:
                        result = {"content": [{"type": "text", "text":
                                  f"[sluice] The output of '{tool}' was withheld: it contains a likely prompt "
                                  "injection (" + ", ".join(sorted({f.code for f in inj})) + ")."}],
                                  "isError": True}
                else:
                    decision = "warn"

        if det.redact_secrets and enforce and decision != "block":
            redactions: list[Finding] = []

            def _redact(s: str) -> str:
                new, found = redact_secrets(s)
                redactions.extend(found)
                return new
            result = _map_texts(result, _redact)
            findings.extend(redactions)
            if redactions and decision == "allow":
                decision = "redact"

        if findings:
            self.audit.log("result", tool=tool, decision=decision, labels=sorted(labels),
                           findings=[f.to_dict() for f in findings])
            for f in findings:
                log.warning("[%s] %s in %s output: %s", self.server, f.code, tool, f.message)
        return {**msg, "result": result}

    def _on_resource(self, msg: JSON) -> JSON:
        result = msg["result"]
        if not isinstance(result, dict):
            return msg
        text = _collect_texts(result)
        if self.policy.detect.strip_hidden_unicode and self.policy.enforce:
            result = _map_texts(result, strip_hidden)
        if text and self.policy.flow.enabled:
            self.flow.record_private(self.server, "resources/read", strip_hidden(text))
        return {**msg, "result": result}

    # ------------------------------------------------------------ tools/list

    def _on_tools_list(self, msg: JSON) -> JSON:
        result = msg["result"]
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return msg
        enforce = self.policy.enforce
        names = [str(t.get("name", "")) for t in tools if isinstance(t, dict)]
        kept: list[JSON] = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name", ""))
            labels = self.policy.labels_for(self.server, name, tool)
            info = ToolInfo(labels)

            if self.policy.is_hidden(self.server, name):
                self.tools[name] = info
                info.quarantine = "tool is disabled by policy"
                self.audit.log("tool_hidden", tool=name, decision="block", reason="denied by policy")
                if enforce:
                    continue

            if self.policy.detect.tool_poisoning != "off":
                info.findings = scan_tool(tool, names)
                if info.findings:
                    severe = at_least(info.findings, "high")
                    quarantine = severe and self.policy.detect.tool_poisoning == "block"
                    if quarantine:
                        info.quarantine = "tool metadata contains injected instructions (" + ", ".join(
                            sorted({f.code for f in info.findings if at_least([f], "high")})) + ")"
                    self.audit.log("tool_poisoning", tool=name,
                                   decision=("block" if enforce else "would_block") if quarantine else "warn",
                                   findings=[f.to_dict() for f in info.findings])
                    log.warning("[%s] tool '%s' metadata findings: %s", self.server, name,
                                ", ".join(f.code for f in info.findings))

            if self.policy.pinning.enabled:
                pin = self.pins.check(self.server, tool)
                if pin.status == "changed":
                    block = self.policy.pinning.on_change == "block"
                    if block:
                        info.quarantine = (f"tool definition changed since approval ({', '.join(pin.changed_fields)}); "
                                           f"possible rug pull -- review, then run "
                                           f"`sluice pins approve {self.server} {name}`")
                    self.audit.log("rug_pull", tool=name,
                                   decision=("block" if enforce else "would_block") if block else "warn",
                                   changed=list(pin.changed_fields))
                    log.warning("[%s] tool '%s' changed since it was pinned: %s",
                                self.server, name, ", ".join(pin.changed_fields))
                elif pin.status == "new":
                    self.audit.log("tool_pinned", tool=name, decision="info", labels=sorted(labels))

            self.tools[name] = info
            if info.quarantine and enforce:
                continue
            if self.policy.detect.strip_hidden_unicode and enforce:
                tool = _sanitize_tool(tool)
            kept.append(tool)

        if len(kept) != len(tools):
            log.warning("[%s] exposing %d of %d tools", self.server, len(kept), len(tools))
        return {**msg, "result": {**result, "tools": kept}}


def _sanitize_tool(tool: JSON) -> JSON:
    def walk(node: Any) -> Any:
        if isinstance(node, str):
            return strip_hidden(node)
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        return node
    return walk(copy.deepcopy(tool))


def _preview(args: Any, limit: int = 300) -> str:
    text = json.dumps(args, ensure_ascii=False, default=str)
    text, _ = redact_secrets(text)
    return text if len(text) <= limit else text[:limit] + "…"
