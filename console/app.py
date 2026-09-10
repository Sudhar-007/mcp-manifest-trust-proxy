"""Trust console: one page that renders decisions the proxy already made.

It computes no security state of its own. Two inputs, each used for the one
thing only it can provide:

  the proxy POSTs live state   quarantine is in-memory in the proxy, and for a
  to /api/proxy-state          modified tool trust.db still holds the OLD text,
                               so the live view cannot come from the database.

  the console polls trust.db   the audit table is the event log, already
  once a second for new        append-only and complete, including rows written
  audit rows                   during tool calls when no refresh happens.

The one write path is /api/approve, which re-pins a tool's current definition
and re-signs the server root. It refuses while the description still has
findings: an approve button must not become a way to wave an attack through.

    python -m console.app        then open http://127.0.0.1:8765
"""

from __future__ import annotations

import asyncio
import sqlite3
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from proxy import keys
from proxy.canonical import leaf_hash
from proxy.detect import agent_directed_imperatives, cross_server_refs
from proxy.drift import root_message
from proxy.merkle import merkle_root
from proxy.store import DB_PATH, TrustStore

STATIC_DIR = Path(__file__).resolve().parent / "static"
POLL_SECONDS = 1.0
EVENT_LIMIT = 200
HOST = "127.0.0.1"
PORT = 8765

AUDIT_COLUMNS = ("id", "timestamp", "server", "tool", "event", "detail")

# Database status -> the short "why" shown next to the pill. The proxy's own
# pills win when it is connected; these are the fallback read from trust.db.
DB_STATUS_WHY = {
    "active": "approved and matching its pin",
    "suspended": "changed after approval; awaiting re-approval",
    "pending_approval": "added after approval, never approved",
}


class Live:
    """Everything the console holds in memory. Small on purpose."""

    snapshot: dict[str, Any] | None = None
    clients: set[WebSocket] = set()
    last_audit_id: int = 0


live = Live()


# --------------------------------------------------------------------------
# trust.db reads. Read-only and tolerant: the page must render before the
# proxy has ever run, when the file does not exist at all.
# --------------------------------------------------------------------------


def _read_only_connection() -> sqlite3.Connection | None:
    if not DB_PATH.exists():
        return None
    try:
        return sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return None


def read_audit(after: int = 0, limit: int = EVENT_LIMIT) -> list[dict[str, Any]]:
    """Audit rows with id > `after`, newest first."""
    conn = _read_only_connection()
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT id, timestamp, server, tool, event, detail FROM audit"
            " WHERE id > ? ORDER BY id DESC LIMIT ?",
            (after, limit),
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return [dict(zip(AUDIT_COLUMNS, row)) for row in rows]


def state_from_db() -> dict[str, Any]:
    """Fallback view when the proxy has never pushed: pins only, no live text."""
    servers: list[dict[str, Any]] = []
    conn = _read_only_connection()
    if conn is not None:
        try:
            for name, root, first_approved in conn.execute(
                "SELECT name, signed_root, first_approved_at FROM servers ORDER BY name"
            ).fetchall():
                tools = [
                    {
                        "name": tool_name,
                        "pills": [[status, DB_STATUS_WHY.get(status, status)]],
                        "needs_review": False,
                        "drift_kind": None,
                        "bucket": None,
                        "bucket_why": None,
                        "diff": "",
                        "description": description,
                        "definition": None,
                        "pinned_description": description,
                        "pinned_leaf": leaf,
                        "findings": [],
                    }
                    for tool_name, status, description, leaf in conn.execute(
                        "SELECT tool_name, status, description_text, leaf_hash FROM tools"
                        " WHERE server_name = ? ORDER BY tool_name",
                        (name,),
                    ).fetchall()
                ]
                servers.append(
                    {
                        "name": name,
                        "verdict": "NOT CONNECTED",
                        "detail": "read from trust.db; the proxy is not running",
                        "pinned_root": root,
                        "first_approved_at": first_approved,
                        "tools": tools,
                    }
                )
        except sqlite3.Error:
            servers = []
        finally:
            conn.close()
    return {"trigger": "trust.db", "registry": {}, "servers": servers}


# --------------------------------------------------------------------------
# WebSocket fan-out
# --------------------------------------------------------------------------


async def broadcast(message: dict[str, Any]) -> None:
    for client in list(live.clients):
        try:
            await client.send_json(message)
        except Exception:  # noqa: BLE001 - a dead socket must not stop the others
            live.clients.discard(client)


async def tail_audit() -> None:
    """Poll trust.db for new audit rows and push them to every open page."""
    while True:
        try:
            rows = read_audit(live.last_audit_id)
            if rows:
                live.last_audit_id = rows[0]["id"]  # newest first
                await broadcast({"type": "events", "events": rows})
        except Exception:  # noqa: BLE001 - the tailer must outlive any single bad read
            pass
        await asyncio.sleep(POLL_SECONDS)


@asynccontextmanager
async def lifespan(_: FastAPI):
    newest = read_audit(0, 1)
    live.last_audit_id = newest[0]["id"] if newest else 0
    task = asyncio.create_task(tail_audit())
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="MCP trust console", lifespan=lifespan)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/state")
async def api_state() -> dict[str, Any]:
    if live.snapshot is not None:
        return {"connected": True, **live.snapshot}
    return {"connected": False, **state_from_db()}


@app.get("/api/events")
async def api_events(after: int = 0) -> dict[str, Any]:
    return {"events": read_audit(after)}


@app.post("/api/proxy-state")
async def api_proxy_state(payload: dict[str, Any]) -> dict[str, Any]:
    live.snapshot = payload
    await broadcast({"type": "state"})
    return {"ok": True}


class ApproveRequest(BaseModel):
    server: str
    tool: str


def _refuse(reason: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=409, content={"error": reason, **extra})


@app.post("/api/approve")
async def api_approve(request: ApproveRequest) -> Any:
    """Re-pin one tool's current definition and re-sign its server root."""
    snapshot = live.snapshot
    if snapshot is None:
        return _refuse("The proxy is not connected, so there is no current definition to approve.")

    server = next((s for s in snapshot["servers"] if s["name"] == request.server), None)
    if server is None:
        return _refuse(f"Unknown server {request.server!r}.")
    tool = next((t for t in server["tools"] if t["name"] == request.tool), None)
    if tool is None:
        return _refuse(f"Unknown tool {request.tool!r} on {request.server!r}.")
    if tool["definition"] is None:
        return _refuse("The server no longer offers this tool, so there is no current definition to pin.")

    description = tool["description"]
    findings = agent_directed_imperatives(description) + cross_server_refs(
        description, snapshot.get("registry") or {}, request.server
    )
    if findings:
        return _refuse(
            "Refused: this description still has description-guard findings. "
            "Approving would pin the injected instruction as trusted.",
            findings=[finding.describe() for finding in findings],
        )

    leaf = leaf_hash(tool["definition"])
    key = keys.load_or_create_key()
    store = TrustStore()
    try:
        records = store.get_tools(request.server)
        # pending_approval rows are not part of the signed root; approving adds this one.
        approved = {name: record.leaf_hash for name, record in records.items() if record.status != "pending_approval"}
        approved[request.tool] = leaf
        root = merkle_root(approved)
        signature = keys.sign(key, root_message(request.server, root))
        store.repin_tool(request.server, request.tool, leaf, description, root, signature)
        store.append_audit(
            request.server,
            request.tool,
            "tool_approved",
            f"approved from the console: current definition re-pinned, leaf={leaf.hex()[:16]}, "
            f"server root re-signed as {root.hex()[:16]}",
        )
    except KeyError as exc:
        return _refuse(str(exc))
    finally:
        store.close()

    # Reflect the database we just wrote. The proxy recomputes drift from
    # (live vs pinned) on its next tools/list, which is what clears the block.
    tool["pills"] = [["active", "re-pinned from the console; effective on the proxy's next tools/list"]]
    tool["needs_review"] = False
    tool["drift_kind"] = None
    tool["findings"] = []
    tool["diff"] = ""
    await broadcast({"type": "state"})
    return {"ok": True, "root": root.hex(), "leaf": leaf.hex()}


@app.websocket("/ws")
async def websocket_endpoint(socket: WebSocket) -> None:
    await socket.accept()
    live.clients.add(socket)
    try:
        await socket.send_json({"type": "events", "events": read_audit(0)})
        while True:
            await socket.receive_text()  # the page never sends; this parks until it disconnects
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - never let one socket take down the server
        pass
    finally:
        live.clients.discard(socket)


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
