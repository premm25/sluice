"""Privacy-preserving session recording, consumed by ``sluice replay`` and ``sluice learn``.

What is recorded, per proxy, in ``state.db``:

``list``      tool definitions as the server advertised them (pre-sanitising)
``call``      tool name, arguments (secrets redacted) and the decision taken
``result``    whether it errored, plus the *fingerprints and token digests*
              of the output -- the same hashes flow tracking already stores.
              Result text is never written to disk.
``resource``  the same, for ``resources/read``

Hashes are enough to replay flow decisions exactly: a replayed sink call is
checked against the same fingerprints the live proxy would have had.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from typing import Any

from sluice.detectors import redact_secrets
from sluice.store import Store


def pack_fingerprints(fps: set[int]) -> bytes:
    return struct.pack(f"<{len(fps)}Q", *sorted(fps))


def unpack_fingerprints(blob: bytes | None) -> set[int]:
    if not blob:
        return set()
    return set(struct.unpack(f"<{len(blob) // 8}Q", blob))


def redact_tree(node: Any) -> Any:
    if isinstance(node, str):
        return redact_secrets(node)[0]
    if isinstance(node, list):
        return [redact_tree(v) for v in node]
    if isinstance(node, dict):
        return {k: redact_tree(v) for k, v in node.items()}
    return node


@dataclass
class Event:
    id: int
    ts: float
    session: str
    server: str
    kind: str
    tool: str | None
    ref: int | None
    data: dict[str, Any]
    fingerprints: set[int] = field(default_factory=set)

    @property
    def args(self) -> dict[str, Any]:
        return self.data.get("args") or {}

    @property
    def decision(self) -> str:
        return self.data.get("decision", "allow")

    @property
    def codes(self) -> list[str]:
        return list(self.data.get("codes", []))


def load_events(store: Store, *, since: float | None = None, sessions: list[str] | None = None,
                server: str | None = None) -> list[Event]:
    return [
        Event(r["id"], r["ts"], r["session"], r["server"], r["kind"], r["tool"], r["ref"],
              json.loads(r["data"]), unpack_fingerprints(r["blob"]))
        for r in store.recordings(sessions=sessions, since=since, server=server)
    ]


def summarize(store: Store) -> list[dict[str, Any]]:
    rows = store.query(
        "SELECT session, MIN(ts) first, MAX(ts) last, COUNT(*) events, "
        "SUM(kind='call') calls, COUNT(DISTINCT server) servers "
        "FROM recordings GROUP BY session ORDER BY last DESC")
    return [dict(r) for r in rows]
