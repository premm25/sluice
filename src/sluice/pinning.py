"""Tool pinning: trust-on-first-use for tool definitions.

A *rug pull* is an MCP server that ships a harmless tool, gets approved, and
later silently changes the tool's description or schema to something
malicious. Sluice hashes each tool's definition the first time it is seen; a
later change quarantines the tool until a human runs ``sluice pins approve``.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from sluice.store import Store

PINNED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def canonical_definition(tool: dict[str, Any]) -> dict[str, Any]:
    return {k: tool[k] for k in PINNED_FIELDS if k in tool}


def tool_digest(tool: dict[str, Any]) -> str:
    blob = json.dumps(canonical_definition(tool), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass
class PinStatus:
    status: str  # "new" | "trusted" | "changed"
    changed_fields: tuple[str, ...] = ()


class PinStore:
    def __init__(self, store: Store):
        self.store = store

    def check(self, server: str, tool: dict[str, Any]) -> PinStatus:
        name = str(tool.get("name", ""))
        digest = tool_digest(tool)
        definition = canonical_definition(tool)
        now = time.time()
        with self.store.transaction() as c:
            row = c.execute("SELECT hash, definition FROM pins WHERE server=? AND tool=?",
                            (server, name)).fetchone()
            if row is None:
                c.execute(
                    "INSERT INTO pins(server, tool, hash, definition, first_seen, updated, status) "
                    "VALUES (?,?,?,?,?,?, 'trusted')",
                    (server, name, digest, json.dumps(definition, sort_keys=True), now, now))
                return PinStatus("new")
            if row[0] == digest:
                c.execute("UPDATE pins SET status='trusted', pending_hash=NULL, pending_definition=NULL "
                          "WHERE server=? AND tool=? AND status!='trusted'", (server, name))
                return PinStatus("trusted")
            old = json.loads(row[1])
            changed = tuple(f for f in PINNED_FIELDS if old.get(f) != definition.get(f))
            c.execute(
                "UPDATE pins SET status='changed', pending_hash=?, pending_definition=?, updated=? "
                "WHERE server=? AND tool=?",
                (digest, json.dumps(definition, sort_keys=True), now, server, name))
            return PinStatus("changed", changed)

    def approve(self, server: str | None = None, tool: str | None = None) -> int:
        sql = ("UPDATE pins SET hash=pending_hash, definition=pending_definition, status='trusted', "
               "pending_hash=NULL, pending_definition=NULL, updated=? WHERE status='changed'")
        params: list[Any] = [time.time()]
        if server:
            sql += " AND server=?"
            params.append(server)
        if tool:
            sql += " AND tool=?"
            params.append(tool)
        return self.store.execute(sql, params).rowcount

    def reset(self, server: str | None = None) -> int:
        if server:
            return self.store.execute("DELETE FROM pins WHERE server=?", (server,)).rowcount
        return self.store.execute("DELETE FROM pins").rowcount

    def other_tool_names(self, server: str) -> set[str]:
        """Names of tools pinned for every *other* server (the shadowing targets)."""
        return {r["tool"] for r in self.store.query("SELECT DISTINCT tool FROM pins WHERE server != ?", (server,))}

    def list(self, server: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT server, tool, hash, status, first_seen, updated, pending_hash FROM pins"
        params: list[Any] = []
        if server:
            sql += " WHERE server=?"
            params.append(server)
        return [dict(r) for r in self.store.query(sql + " ORDER BY server, tool", params)]
