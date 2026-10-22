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
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlsplit

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

    def features(self, text: str) -> tuple[set[int], set[str]]:
        """Fingerprints and token digests of ``text`` -- all that is ever kept of private data."""
        return fingerprint(text, self.k, self.w), {_digest(t) for t in high_value_tokens(text)}

    def record_private(self, server: str, tool: str, text: str) -> int:
        fps, tokens = self.features(text)
        return self.record_private_features(server, tool, fps, tokens)

    def record_private_features(self, server: str, tool: str, fps: set[int], tokens: set[str]) -> int:
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


# --------------------------------------------------------------------------
# Split ("low-and-slow") exfiltration
# --------------------------------------------------------------------------

# Arguments that say *where* data goes rather than carrying it.
DESTINATION_KEYS = {
    "to", "recipient", "recipients", "channel", "channel_id", "chat_id", "email", "address", "cc", "bcc",
    "phone", "webhook", "webhook_url", "endpoint", "host", "destination", "repo", "owner", "user", "username",
}
_URL_SCHEMES = ("http", "https", "ws", "wss", "ftp")


def _leaves(node: Any, path: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _leaves(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _leaves(v, f"{path}[{i}]")
    else:
        yield path, node


def split_streams(arguments: Any) -> tuple[str, dict[str, str]]:
    """Split a sink call's arguments into a destination and named data streams.

    A URL contributes its origin to the destination and its path segments,
    query values and fragment as separate streams, so ``?n=1&d=<chunk>``
    keeps the chunks of ``d`` contiguous even though ``n`` varies.
    """
    destination: list[str] = []
    streams: dict[str, str] = {}
    for path, value in _leaves(arguments):
        if not isinstance(value, str) or not value:
            continue
        key = path.rsplit(".", 1)[-1].split("[", 1)[0].lower()
        url = urlsplit(value) if "://" in value else None
        if url and url.scheme.lower() in _URL_SCHEMES and url.netloc:
            destination.append(f"{url.scheme.lower()}://{url.netloc.lower()}")
            for i, segment in enumerate(s for s in url.path.split("/") if s):
                streams[f"{path}/{i}"] = unquote(segment)
            for part in url.query.split("&"):
                if part:
                    name, _, val = part.partition("=")
                    # unquote (not unquote_plus): '+' is part of the base64 alphabet
                    streams[f"{path}?{unquote(name)}"] = streams.get(f"{path}?{unquote(name)}", "") + unquote(val)
            if url.fragment:
                streams[f"{path}#"] = unquote(url.fragment)
        elif key in DESTINATION_KEYS:
            destination.append(f"{key}={value.strip().lower()}")
        else:
            streams[path] = value
    return "|".join(sorted(set(destination))) or "-", streams


class SplitTracker:
    """Remembers recent outbound data per (sink, destination, stream).

    Lives in process memory only: outbound fragments are never persisted.
    """

    def __init__(self, window: float = 600, max_chars: int = 20_000):
        self.window = window
        self.max_chars = max_chars
        self._buffers: dict[tuple[str, str], deque[tuple[float, str]]] = {}

    def _prune(self, key: tuple[str, str], now: float) -> deque[tuple[float, str]]:
        buf = self._buffers.setdefault(key, deque())
        while buf and now - buf[0][0] > self.window:
            buf.popleft()
        return buf

    def accumulated(self, sink: str, streams: dict[str, str], now: float) -> dict[str, tuple[int, str]]:
        """For streams with history, ``{stream: (number_of_calls, concatenated_data)}`` incl. this call."""
        out: dict[str, tuple[int, str]] = {}
        for name, value in streams.items():
            buf = self._prune((sink, name), now)
            if buf:
                out[name] = (len(buf) + 1, "".join(v for _, v in buf) + value)
        return out

    def commit(self, sink: str, streams: dict[str, str], now: float) -> None:
        for name, value in streams.items():
            buf = self._prune((sink, name), now)
            buf.append((now, value))
            total = sum(len(v) for _, v in buf)
            while len(buf) > 1 and total > self.max_chars:
                total -= len(buf.popleft()[1])
