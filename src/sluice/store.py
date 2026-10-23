"""Shared, cross-process state backed by SQLite (WAL mode).

An MCP client (Claude Desktop, Cursor, VS Code, ...) launches one process per
server, so one Sluice proxy runs per server. The *lethal trifecta* usually
spans servers -- private data from one, untrusted content from a second, an
exfiltration channel on a third -- so the proxies must share taint state.

They do so through this database. Proxies launched by the same client share a
*session* (by default the client's PID -- see :func:`default_session`), and
taint is scoped to that session with a TTL.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints(
    session TEXT NOT NULL, fp INTEGER NOT NULL, server TEXT, tool TEXT, ts REAL,
    UNIQUE(session, fp, server, tool));
CREATE INDEX IF NOT EXISTS ix_fp ON fingerprints(session, fp);
CREATE TABLE IF NOT EXISTS tokens(
    session TEXT NOT NULL, digest TEXT NOT NULL, server TEXT, tool TEXT, ts REAL,
    UNIQUE(session, digest, server, tool));
CREATE INDEX IF NOT EXISTS ix_tok ON tokens(session, digest);
CREATE TABLE IF NOT EXISTS taint(
    session TEXT NOT NULL, label TEXT NOT NULL, server TEXT, tool TEXT, ts REAL);
CREATE INDEX IF NOT EXISTS ix_taint ON taint(session, label, ts);
CREATE TABLE IF NOT EXISTS pins(
    server TEXT NOT NULL, tool TEXT NOT NULL, hash TEXT NOT NULL, definition TEXT NOT NULL,
    first_seen REAL, updated REAL, status TEXT NOT NULL DEFAULT 'trusted',
    pending_hash TEXT, pending_definition TEXT,
    PRIMARY KEY(server, tool));
CREATE TABLE IF NOT EXISTS audit(
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, session TEXT, server TEXT,
    event TEXT NOT NULL, tool TEXT, decision TEXT, detail TEXT NOT NULL,
    prev TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS recordings(
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, session TEXT, server TEXT,
    kind TEXT NOT NULL, tool TEXT, ref INTEGER, data TEXT NOT NULL, blob BLOB);
CREATE INDEX IF NOT EXISTS ix_rec ON recordings(session, id);
"""

_CHUNK = 500


def sluice_home() -> Path:
    home = os.environ.get("SLUICE_HOME")
    path = Path(home).expanduser() if home else Path.home() / ".sluice"
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_db_path() -> Path:
    return sluice_home() / "state.db"


def default_session() -> str:
    """Proxies spawned by the same MCP client share the client's PID."""
    explicit = os.environ.get("SLUICE_SESSION")
    if explicit:
        return explicit
    from sluice.procs import client_pid
    return f"client-{client_pid()}"


class Store:
    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = str(path or default_db_path())
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            # Several proxies of one client start at the same moment. A read that
            # upgrades to a write fails instantly when it races another writer
            # (SQLite won't wait, to avoid deadlock), so take the write lock up
            # front with BEGIN IMMEDIATE and retry the one-off WAL switch.
            for attempt in range(100):
                try:
                    self.conn.execute("PRAGMA journal_mode=WAL")
                    self.conn.executescript(f"BEGIN IMMEDIATE;{SCHEMA}COMMIT;")
                    break
                except sqlite3.OperationalError as e:
                    if self.conn.in_transaction:
                        self.conn.execute("ROLLBACK")
                    if "locked" not in str(e) or attempt == 99:
                        raise
                    time.sleep(0.05)
            self.conn.execute("PRAGMA synchronous=NORMAL")

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # -- generic helpers -----------------------------------------------------

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self.conn.execute(sql, tuple(params))

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, tuple(params)).fetchall()

    def transaction(self) -> _Tx:
        return _Tx(self)

    # -- taint & fingerprints -----------------------------------------------

    def add_fingerprints(self, session: str, fps: Iterable[int], server: str, tool: str) -> None:
        now = time.time()
        rows = [(session, fp, server, tool, now) for fp in fps]
        if not rows:
            return
        with self.transaction() as c:
            c.executemany(
                "INSERT OR IGNORE INTO fingerprints(session, fp, server, tool, ts) VALUES (?,?,?,?,?)", rows)

    def add_tokens(self, session: str, digests: Iterable[str], server: str, tool: str) -> None:
        now = time.time()
        rows = [(session, d, server, tool, now) for d in digests]
        if not rows:
            return
        with self.transaction() as c:
            c.executemany(
                "INSERT OR IGNORE INTO tokens(session, digest, server, tool, ts) VALUES (?,?,?,?,?)", rows)

    def match_fingerprints(self, session: str, fps: Iterable[int], since: float) -> list[sqlite3.Row]:
        return self._match("fingerprints", "fp", session, list(fps), since)

    def match_tokens(self, session: str, digests: Iterable[str], since: float) -> list[sqlite3.Row]:
        return self._match("tokens", "digest", session, list(digests), since)

    def _match(self, table: str, col: str, session: str, values: list[Any], since: float) -> list[sqlite3.Row]:
        out: list[sqlite3.Row] = []
        for i in range(0, len(values), _CHUNK):
            chunk = values[i:i + _CHUNK]
            marks = ",".join("?" * len(chunk))
            out.extend(self.query(
                f"SELECT DISTINCT {col} AS v, server, tool FROM {table} "
                f"WHERE session = ? AND ts >= ? AND {col} IN ({marks})",
                [session, since, *chunk]))
        return out

    def add_taint(self, session: str, label: str, server: str, tool: str) -> None:
        self.execute("INSERT INTO taint(session, label, server, tool, ts) VALUES (?,?,?,?,?)",
                     (session, label, server, tool, time.time()))

    def taint_sources(self, session: str, label: str, since: float) -> list[tuple[str, str]]:
        rows = self.query(
            "SELECT DISTINCT server, tool FROM taint WHERE session = ? AND label = ? AND ts >= ?",
            (session, label, since))
        return [(r["server"], r["tool"]) for r in rows]

    def clear_session(self, session: str) -> None:
        with self.transaction() as c:
            for table in ("fingerprints", "tokens", "taint"):
                c.execute(f"DELETE FROM {table} WHERE session = ?", (session,))

    def gc(self, older_than: float, recordings_older_than: float | None = None) -> None:
        now = time.time()
        with self.transaction() as c:
            for table in ("fingerprints", "tokens", "taint"):
                c.execute(f"DELETE FROM {table} WHERE ts < ?", (now - older_than,))
            if recordings_older_than is not None:
                c.execute("DELETE FROM recordings WHERE ts < ?", (now - recordings_older_than,))

    # -- recordings (for `sluice replay` and `sluice learn`) -------------------

    def add_recording(self, session: str, server: str, kind: str, tool: str | None,
                      data: dict[str, Any], blob: bytes | None = None, ref: int | None = None,
                      ts: float | None = None) -> int:
        cur = self.execute(
            "INSERT INTO recordings(ts, session, server, kind, tool, ref, data, blob) VALUES (?,?,?,?,?,?,?,?)",
            (time.time() if ts is None else ts, session, server, kind, tool, ref,
             json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str), blob))
        return int(cur.lastrowid or 0)

    def recordings(self, sessions: Iterable[str] | None = None, since: float | None = None,
                   server: str | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM recordings WHERE 1=1"
        params: list[Any] = []
        if sessions is not None:
            sessions = list(sessions)
            sql += f" AND session IN ({','.join('?' * len(sessions))})" if sessions else " AND 0"
            params.extend(sessions)
        if since is not None:
            sql += " AND ts >= ?"
            params.append(since)
        if server is not None:
            sql += " AND server = ?"
            params.append(server)
        return self.query(sql + " ORDER BY id", params)


class _Tx:
    """``BEGIN IMMEDIATE`` transaction: serialises writers across processes."""

    def __init__(self, store: Store):
        self.store = store

    def __enter__(self) -> sqlite3.Connection:
        self.store._lock.acquire()
        self.store.conn.execute("BEGIN IMMEDIATE")
        return self.store.conn

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        try:
            self.store.conn.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self.store._lock.release()
