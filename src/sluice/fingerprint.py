"""Content fingerprinting for data-flow tracking.

Sluice needs to answer one question fast: *does this outbound tool call carry
data that came out of a private source earlier in the session?* The model may
paraphrase, reformat, re-case or encode that data, so exact matching is not
enough, and storing the raw private data would itself be a liability.

We use **winnowing** (Schleimer, Wilkerson & Aiken, SIGMOD 2003 -- the
algorithm behind the MOSS plagiarism detector):

1. Normalise text: lowercase, keep only alphanumerics. Whitespace, punctuation
   and case changes therefore don't break matches.
2. Hash every k-gram with a Rabin-Karp rolling hash (deterministic across
   processes, unlike Python's ``hash``).
3. Slide a window of ``w`` hashes and keep the minimum of each window.

Guarantee: any shared normalised substring of length >= ``k + w - 1`` produces
at least one shared fingerprint, while only ~``2/(w+1)`` of hashes are stored.
Only hashes are persisted -- never the private text.

Encoded exfiltration (``?d=<base64>``) is handled by :func:`decoded_views`,
which peels URL-encoding, base64 and hex layers before fingerprinting.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections import deque
from urllib.parse import unquote_plus

MOD = (1 << 61) - 1  # Mersenne prime; hashes fit in a signed 64-bit SQLite INTEGER
BASE = 1_000_003

DEFAULT_K = 24
DEFAULT_W = 12


_NON_ALNUM_RE = re.compile(r"[\W_]+")


def normalize(text: str) -> str:
    return _NON_ALNUM_RE.sub("", text.lower())


def kgram_hashes(s: str, k: int) -> list[int]:
    codes = s.encode("utf-8")  # iterating bytes yields ints: no per-char ord()
    n = len(codes)
    if n < k:
        return []
    top = pow(BASE, k - 1, MOD)
    h = 0
    for c in codes[:k]:
        h = (h * BASE + c) % MOD
    out = [h]
    for i in range(k, n):
        h = ((h - codes[i - k] * top) * BASE + codes[i]) % MOD
        out.append(h)
    return out


def winnow(hashes: list[int], w: int) -> set[int]:
    """Select the (rightmost) minimum hash of every window of ``w`` hashes. O(n)."""
    if not hashes:
        return set()
    if len(hashes) <= w:
        return {min(hashes)}
    out: set[int] = set()
    window: deque[int] = deque()  # indices, values strictly increasing
    for i, h in enumerate(hashes):
        while window and hashes[window[-1]] >= h:
            window.pop()
        window.append(i)
        if window[0] <= i - w:
            window.popleft()
        if i >= w - 1:
            out.add(hashes[window[0]])
    return out


def fingerprint(text: str, k: int = DEFAULT_K, w: int = DEFAULT_W) -> set[int]:
    return winnow(kgram_hashes(normalize(text), k), w)


# --------------------------------------------------------------------------
# Peeling encodings
# --------------------------------------------------------------------------

_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")


def _printable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    good = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return text if good / len(text) >= 0.9 else None


def _b64_decode(segment: str) -> str | None:
    seg = segment.rstrip("=")
    padded = seg + "=" * (-len(seg) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = _printable(decoder(padded))
        except (binascii.Error, ValueError):
            continue
        if decoded:
            return decoded
    return None


def decoded_views(text: str, depth: int = 3, max_views: int = 64) -> list[tuple[str, str]]:
    """Return ``(view, encoding)`` for ``text`` and every decoding peeled off it.

    The original text has encoding ``"plain"``; decoded views are labelled with
    the chain of layers removed, e.g. ``"url+base64"``. Nested encodings are
    peeled up to ``depth`` layers.
    """
    views = [(text, "plain")]
    seen = {text}
    frontier = [(text, "")]
    for _ in range(depth):
        nxt: list[tuple[str, str]] = []
        for t, chain in frontier:
            candidates: list[tuple[str, str]] = []
            # '+' vs ' ' is irrelevant after normalisation; only real %XX escapes hide data.
            if _PCT_RE.search(t):
                candidates.append((unquote_plus(t), "url"))
            for m in _B64_RE.finditer(t):
                decoded = _b64_decode(m.group())
                if decoded:
                    candidates.append((decoded, "base64"))
            for m in _HEX_RE.finditer(t):
                decoded = _printable(bytes.fromhex(m.group()))
                if decoded:
                    candidates.append((decoded, "hex"))
            for c, layer in candidates:
                if c not in seen:
                    seen.add(c)
                    label = f"{chain}+{layer}" if chain else layer
                    nxt.append((c, label))
                    views.append((c, label))
                    if len(views) >= max_views:
                        return views
        if not nxt:
            break
        frontier = nxt
    return views
