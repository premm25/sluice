"""Session-level information-flow tracking.

Tools carry *labels*:

* ``private``   -- returns data the user would not want leaked (files, mail, DBs)
* ``untrusted`` -- returns content an attacker can influence (web, issues, inbox)
* ``sink``      -- can move data out of the machine (HTTP, email, chat, PRs)

Simon Willison's *lethal trifecta*: an agent session that has (1) touched
private data, (2) ingested untrusted content and (3) has a sink available can
be steered by a prompt injection into exfiltrating that data.

Sluice enforces two checks when a sink is called:

``trifecta``      coarse: session has both private and untrusted taint.
``exfiltration``  precise: the sink's arguments contain (possibly encoded)
                  content fingerprinted from a private source.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from sluice.detectors import high_value_tokens
from sluice.fingerprint import DEFAULT_K, DEFAULT_W, decoded_views, fingerprint
from sluice.store import Store

PRIVATE = "private"
UNTRUSTED = "untrusted"
SINK = "sink"
LABELS = (PRIVATE, UNTRUSTED, SINK)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:32]


def iter_strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from iter_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from iter_strings(v)
    elif node is not None and not isinstance(node, bool):
        yield json.dumps(node)


@dataclass
class LeakReport:
    fingerprint_matches: int = 0
    token_matches: int = 0
    sources: set[tuple[str, str]] = field(default_factory=set)
    encodings: set[str] = field(default_factory=set)

    def leaked(self, min_matches: int) -> bool:
        return self.token_matches > 0 or self.fingerprint_matches >= min_matches

    def describe(self) -> str:
        src = ", ".join(sorted(f"{s}/{t}" for s, t in self.sources)) or "unknown"
        parts = []
        if self.fingerprint_matches:
            parts.append(f"{self.fingerprint_matches} content fingerprint(s)")
        if self.token_matches:
            parts.append(f"{self.token_matches} secret/token value(s)")
        how = f" (hidden via {', '.join(sorted(self.encodings))} encoding)" if self.encodings else ""
        return f"arguments contain {' and '.join(parts)} from private source {src}{how}"


@dataclass
class TaintState:
    private: list[tuple[str, str]]
    untrusted: list[tuple[str, str]]

    @property
    def trifecta(self) -> bool:
        return bool(self.private and self.untrusted)


class FlowTracker:
    def __init__(self, store: Store, session: str, ttl: float = 12 * 3600,
                 k: int = DEFAULT_K, w: int = DEFAULT_W):
        self.store = store
        self.session = session
        self.ttl = ttl
        self.k = k
        self.w = w

    @property
    def _since(self) -> float:
        return time.time() - self.ttl

    def record_private(self, server: str, tool: str, text: str) -> int:
        fps = fingerprint(text, self.k, self.w)
        tokens = {_digest(t) for t in high_value_tokens(text)}
        self.store.add_fingerprints(self.session, fps, server, tool)
        self.store.add_tokens(self.session, tokens, server, tool)
        self.store.add_taint(self.session, PRIVATE, server, tool)
        return len(fps) + len(tokens)

    def record_untrusted(self, server: str, tool: str) -> None:
        self.store.add_taint(self.session, UNTRUSTED, server, tool)

    def taint(self) -> TaintState:
        return TaintState(
            self.store.taint_sources(self.session, PRIVATE, self._since),
            self.store.taint_sources(self.session, UNTRUSTED, self._since),
        )

    def check_sink(self, arguments: Any) -> LeakReport:
        report = LeakReport()
        fp_origin: dict[int, str] = {}
        tok_origin: dict[str, str] = {}
        for s in iter_strings(arguments):
            for view, label in decoded_views(s):
                for fp in fingerprint(view, self.k, self.w):
                    fp_origin.setdefault(fp, label)
                for tok in high_value_tokens(view):
                    tok_origin.setdefault(_digest(tok), label)
        if not fp_origin and not tok_origin:
            return report

        fp_rows = self.store.match_fingerprints(self.session, fp_origin, self._since)
        tok_rows = self.store.match_tokens(self.session, tok_origin, self._since)
        matched_fps = {r["v"] for r in fp_rows}
        matched_toks = {r["v"] for r in tok_rows}
        report.fingerprint_matches = len(matched_fps)
        report.token_matches = len(matched_toks)
        report.sources = {(r["server"], r["tool"]) for r in [*fp_rows, *tok_rows]}
        report.encodings = {fp_origin[f] for f in matched_fps} | {tok_origin[t] for t in matched_toks}
        report.encodings.discard("plain")
        return report
