"""SQLite trust store at proxy/trust.db.

  servers  one row per upstream: the signed Merkle root of its approved tools
  tools    one row per tool: pinned leaf hash + description, and current status
  audit    append-only event log

The audit table is append-only twice over: this module contains no statement
that modifies or removes audit rows, and SQLite triggers abort any attempt that
reaches the table anyway (for example from a hand-run sqlite3 session).

Run `python -m proxy.store` to print all three tables.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "trust.db"

STATUSES = ("active", "suspended", "pending_approval")

SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    name              TEXT PRIMARY KEY,
    first_approved_at TEXT NOT NULL,
    signed_root       TEXT NOT NULL,  -- hex Merkle root over the approved tools' leaf hashes
    root_signature    TEXT NOT NULL   -- hex Ed25519 signature over (server name, root)
);

CREATE TABLE IF NOT EXISTS tools (
    server_name      TEXT NOT NULL,
    tool_name        TEXT NOT NULL,
    leaf_hash        TEXT NOT NULL,  -- hex; for pending_approval rows, the unapproved live hash
    description_text TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'pending_approval')),
    pinned_at        TEXT NOT NULL,
    PRIMARY KEY (server_name, tool_name)
);

CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    server    TEXT,
    tool      TEXT,
    event     TEXT NOT NULL,
    detail    TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit table is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit table is append-only'); END;
"""


@dataclass(frozen=True)
class PinnedServer:
    name: str
    first_approved_at: str
    signed_root: bytes
    root_signature: bytes


@dataclass(frozen=True)
class ToolRecord:
    server_name: str
    tool_name: str
    leaf_hash: bytes
    description_text: str
    status: str
    pinned_at: str


@dataclass(frozen=True)
class AuditEntry:
    id: int
    timestamp: str
    server: str | None
    tool: str | None
    event: str
    detail: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TrustStore:
    def __init__(self, path: Path = DB_PATH) -> None:
        self.path = path
        self._conn = sqlite3.connect(path)
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # ---- reads. Hex decoding raises ValueError on a hand-edited, malformed row.

    def get_server(self, name: str) -> PinnedServer | None:
        row = self._conn.execute(
            "SELECT name, first_approved_at, signed_root, root_signature FROM servers WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            return None
        return PinnedServer(row[0], row[1], bytes.fromhex(row[2]), bytes.fromhex(row[3]))

    def list_servers(self) -> list[PinnedServer]:
        rows = self._conn.execute("SELECT name FROM servers ORDER BY name").fetchall()
        return [server for (name,) in rows if (server := self.get_server(name)) is not None]

    def get_tools(self, server_name: str) -> dict[str, ToolRecord]:
        rows = self._conn.execute(
            "SELECT server_name, tool_name, leaf_hash, description_text, status, pinned_at"
            " FROM tools WHERE server_name = ? ORDER BY tool_name",
            (server_name,),
        ).fetchall()
        return {row[1]: ToolRecord(row[0], row[1], bytes.fromhex(row[2]), row[3], row[4], row[5]) for row in rows}

    def audit_entries(self) -> list[AuditEntry]:
        rows = self._conn.execute("SELECT id, timestamp, server, tool, event, detail FROM audit ORDER BY id").fetchall()
        return [AuditEntry(*row) for row in rows]

    # ---- writes

    def pin_server(
        self, name: str, signed_root: bytes, root_signature: bytes, tools: Iterable[tuple[str, bytes, str]]
    ) -> None:
        """First approval of a server: its signed root plus every tool, all active, in one transaction."""
        now = utc_now()
        with self._conn:
            self._conn.execute(
                "INSERT INTO servers (name, first_approved_at, signed_root, root_signature) VALUES (?, ?, ?, ?)",
                (name, now, signed_root.hex(), root_signature.hex()),
            )
            self._conn.executemany(
                "INSERT INTO tools (server_name, tool_name, leaf_hash, description_text, status, pinned_at)"
                " VALUES (?, ?, ?, ?, 'active', ?)",
                [(name, tool_name, leaf.hex(), description, now) for tool_name, leaf, description in tools],
            )

    def add_pending_tool(self, server_name: str, tool_name: str, leaf_hash: bytes, description_text: str) -> None:
        """Record a tool that appeared after approval. Can never overwrite an approved row."""
        with self._conn:
            self._conn.execute(
                "INSERT INTO tools (server_name, tool_name, leaf_hash, description_text, status, pinned_at)"
                " VALUES (?, ?, ?, ?, 'pending_approval', ?)"
                " ON CONFLICT (server_name, tool_name) DO UPDATE"
                " SET leaf_hash = excluded.leaf_hash, description_text = excluded.description_text"
                " WHERE tools.status = 'pending_approval'",
                (server_name, tool_name, leaf_hash.hex(), description_text, utc_now()),
            )

    def set_status(self, server_name: str, tool_name: str, status: str) -> None:
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}")
        with self._conn:
            self._conn.execute(
                "UPDATE tools SET status = ? WHERE server_name = ? AND tool_name = ?", (status, server_name, tool_name)
            )

    def repin_tool(
        self,
        server_name: str,
        tool_name: str,
        leaf_hash: bytes,
        description_text: str,
        signed_root: bytes,
        root_signature: bytes,
    ) -> None:
        """Approve a tool's current definition: swap its leaf, then re-sign the server root.

        Both writes happen in one transaction. A root that did not match the tool
        rows would read as TAMPERED on the next check, so they must never be
        allowed to land separately.
        """
        with self._conn:
            updated = self._conn.execute(
                "UPDATE tools SET leaf_hash = ?, description_text = ?, status = 'active', pinned_at = ?"
                " WHERE server_name = ? AND tool_name = ?",
                (leaf_hash.hex(), description_text, utc_now(), server_name, tool_name),
            ).rowcount
            if updated == 0:
                raise KeyError(f"no tool row for {server_name}/{tool_name}")
            self._conn.execute(
                "UPDATE servers SET signed_root = ?, root_signature = ? WHERE name = ?",
                (signed_root.hex(), root_signature.hex(), server_name),
            )

    def append_audit(self, server: str | None, tool: str | None, event: str, detail: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO audit (timestamp, server, tool, event, detail) VALUES (?, ?, ?, ?, ?)",
                (utc_now(), server, tool, event, detail),
            )


def print_tables(store: TrustStore) -> None:
    print("SERVERS")
    for server in store.list_servers():
        print(
            f"  {server.name:<8} first approved {server.first_approved_at}"
            f"  root {server.signed_root.hex()[:16]}...  signature {server.root_signature.hex()[:16]}..."
        )
        print("\n  TOOLS")
        for tool in store.get_tools(server.name).values():
            print(f"    {tool.tool_name:<12} {tool.status:<17} leaf {tool.leaf_hash.hex()[:16]}...  pinned {tool.pinned_at}")
        print()

    print("AUDIT")
    for entry in store.audit_entries():
        print(f"  #{entry.id:<3} {entry.timestamp}  {entry.server or '-':<6} {entry.tool or '-':<10} {entry.event}")
        print(f"        {entry.detail}")


if __name__ == "__main__":
    if not DB_PATH.exists():
        print(f"No trust store yet at {DB_PATH}. Run the proxy once to create it.")
    else:
        store = TrustStore()
        try:
            print_tables(store)
        finally:
            store.close()
