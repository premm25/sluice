"""Tamper-evident audit log.

Every decision Sluice makes is appended to a hash chain:
``hash_n = SHA-256(hash_{n-1} || canonical(row_n))``. Editing, deleting or
reordering any past row breaks every hash after it, which
:func:`verify` detects. Appends from concurrent proxy processes are
serialised with ``BEGIN IMMEDIATE`` so the chain never forks.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from sluice.store import Store

GENESIS = "0" * 64


def _canonical(ts: float, session: str | None, server: str | None, event: str,
               tool: str | None, decision: str | None, detail: str) -> bytes:
    return json.dumps([ts, session, server, event, tool, decision, detail],
                      separators=(",", ":"), ensure_ascii=False).encode()


def _chain(prev: str, payload: bytes) -> str:
    return hashlib.sha256(prev.encode() + payload).hexdigest()


class AuditLog:
    def __init__(self, store: Store, session: str | None = None, server: str | None = None):
        self.store = store
        self.session = session
        self.server = server

    def log(self, event: str, *, tool: str | None = None, decision: str | None = None,
            **detail: Any) -> str:
        ts = time.time()
        detail_text = json.dumps(detail, sort_keys=True, ensure_ascii=False, default=str)
        with self.store.transaction() as c:
            row = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            digest = _chain(prev, _canonical(ts, self.session, self.server, event, tool, decision, detail_text))
            c.execute(
                "INSERT INTO audit(ts, session, server, event, tool, decision, detail, prev, hash) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (ts, self.session, self.server, event, tool, decision, detail_text, prev, digest))
        return digest


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    broken_at: int | None = None
    reason: str = ""


def verify(store: Store) -> VerifyResult:
    prev = GENESIS
    checked = 0
    for row in store.query("SELECT * FROM audit ORDER BY id"):
        if row["prev"] != prev:
            return VerifyResult(False, checked, row["id"], "chain link broken (row deleted or reordered)")
        expected = _chain(prev, _canonical(row["ts"], row["session"], row["server"], row["event"],
                                           row["tool"], row["decision"], row["detail"]))
        if expected != row["hash"]:
            return VerifyResult(False, checked, row["id"], "row contents were modified")
        prev = row["hash"]
        checked += 1
    return VerifyResult(True, checked)


def events(store: Store, limit: int | None = None, since_id: int = 0) -> list[dict[str, Any]]:
    sql = "SELECT * FROM audit WHERE id > ? ORDER BY id DESC"
    params: list[Any] = [since_id]
    if limit:
        sql += " LIMIT ?"
        params.append(limit)
    rows = store.query(sql, params)
    out = []
    for r in reversed(rows):
        d = dict(r)
        d["detail"] = json.loads(d["detail"])
        out.append(d)
    return out


def stats(store: Store) -> dict[str, Any]:
    by_decision = {r[0] or "-": r[1] for r in store.query(
        "SELECT decision, COUNT(*) FROM audit GROUP BY decision")}
    by_event = {r[0]: r[1] for r in store.query("SELECT event, COUNT(*) FROM audit GROUP BY event")}
    top_blocked = [(r[0], r[1]) for r in store.query(
        "SELECT tool, COUNT(*) c FROM audit WHERE decision='block' AND tool IS NOT NULL "
        "GROUP BY tool ORDER BY c DESC LIMIT 10")]
    total = store.query("SELECT COUNT(*) FROM audit")[0][0]
    return {"total": total, "by_decision": by_decision, "by_event": by_event, "top_blocked": top_blocked}
