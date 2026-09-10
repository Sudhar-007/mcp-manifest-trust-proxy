"""Drift detection: compare a server's live tools against the signed pin.

Verdicts
  FIRST_RUN  nothing pinned for this server yet: pin the live manifest and sign it
  CLEAN      signature verifies and the live root equals the pinned root
  DRIFT      signature verifies but the root differs: localize the changed tools
  TAMPERED   the stored record fails verification: trust.db itself was modified

Tool statuses are recomputed from (pinned leaves, live leaves) on every check,
so flipping a status by hand in trust.db does not unblock anything, and a tool
whose live definition matches its pin again goes back to active.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import keys
from .canonical import leaf_hash
from .merkle import changed_leaves, merkle_root
from .store import TrustStore

SIGNATURE_CONTEXT = b"mcp-trust-proxy/manifest-root/v1"

# The status a tool is put in for each kind of change.
STATUS_FOR_CHANGE = {"modified": "suspended", "removed": "suspended", "added": "pending_approval"}


class Verdict(str, Enum):
    FIRST_RUN = "FIRST_RUN"
    CLEAN = "CLEAN"
    DRIFT = "DRIFT"
    TAMPERED = "TAMPERED"


@dataclass
class ToolChange:
    tool: str
    kind: str  # "added" | "removed" | "modified"
    diff: str  # word-level description diff; "" when there is nothing to show


@dataclass
class DriftReport:
    server: str
    verdict: Verdict
    detail: str
    changes: list[ToolChange] = field(default_factory=list)
    blocked: dict[str, str] = field(default_factory=dict)  # tool name -> "modified" | "added" | "removed" | "tampered"


def root_message(server_name: str, root: bytes) -> bytes:
    """The bytes we sign. Binds the root to the server name so roots cannot be swapped between servers."""
    return SIGNATURE_CONTEXT + b"\x00" + server_name.encode("utf-8") + b"\x00" + root


def check_drift(
    server_name: str,
    live_tools: list[dict[str, Any]],
    *,
    store: TrustStore,
    key: Ed25519PrivateKey,
    trigger: str = "check",
) -> DriftReport:
    """Check `live_tools` (wire-format dicts) against the pin for `server_name`, updating trust.db."""
    live_leaves = {tool["name"]: leaf_hash(tool) for tool in live_tools}
    live_text = {tool["name"]: tool.get("description") or "" for tool in live_tools}
    live_root = merkle_root(live_leaves)

    try:
        pin = store.get_server(server_name)
        records = store.get_tools(server_name)
    except ValueError as exc:
        return _tampered(store, server_name, live_leaves, trigger, f"malformed trust store row ({exc})")

    if pin is None:
        if records:
            return _tampered(store, server_name, live_leaves, trigger, "tool records exist but the server pin is missing")
        signature = keys.sign(key, root_message(server_name, live_root))
        store.pin_server(
            server_name, live_root, signature, [(name, live_leaves[name], live_text[name]) for name in sorted(live_leaves)]
        )
        detail = f"trigger={trigger}; pinned {len(live_leaves)} tools {sorted(live_leaves)}; root={live_root.hex()[:16]}"
        store.append_audit(server_name, None, "pinned_first_run", detail)
        return DriftReport(server_name, Verdict.FIRST_RUN, detail)

    # pending_approval rows were never approved, so they are not part of the signed root.
    approved = {name: record for name, record in records.items() if record.status != "pending_approval"}
    approved_leaves = {name: record.leaf_hash for name, record in approved.items()}

    if not keys.verify(key.public_key(), root_message(server_name, pin.signed_root), pin.root_signature):
        return _tampered(store, server_name, live_leaves, trigger, "stored root signature does not verify")
    if merkle_root(approved_leaves) != pin.signed_root:
        return _tampered(store, server_name, live_leaves, trigger, "stored tool hashes do not rebuild the signed root")

    if live_root == pin.signed_root:
        for name in approved:
            _set_status(store, server_name, approved[name].status, name, "active")
        detail = f"trigger={trigger}; root={live_root.hex()[:16]} matches the signed pin"
        store.append_audit(server_name, None, "verdict_clean", detail)
        return DriftReport(server_name, Verdict.CLEAN, detail)

    delta = changed_leaves(approved_leaves, live_leaves)
    changes: list[ToolChange] = []

    for name in delta.modified:
        diff = _describe_modification(approved[name].description_text, live_text[name])
        changes.append(ToolChange(name, "modified", diff))
        _set_status(store, server_name, approved[name].status, name, "suspended", f"definition changed after approval: {diff}")

    for name in delta.removed:
        changes.append(ToolChange(name, "removed", ""))
        _set_status(store, server_name, approved[name].status, name, "suspended", "server no longer offers this approved tool")

    for name in delta.added:
        changes.append(ToolChange(name, "added", word_diff("", live_text[name])))
        existing = records.get(name)
        if existing is None or existing.leaf_hash != live_leaves[name]:
            store.add_pending_tool(server_name, name, live_leaves[name], live_text[name])
            store.append_audit(server_name, name, "tool_pending_approval", f"new tool after approval: {live_text[name]!r}")

    # Tools that did not change stay (or become again) active.
    for name in approved.keys() - set(delta.modified) - set(delta.removed):
        _set_status(store, server_name, approved[name].status, name, "active")

    summary = "; ".join(
        f"{kind}: {', '.join(names)}"
        for kind, names in (("modified", delta.modified), ("removed", delta.removed), ("added", delta.added))
        if names
    )
    detail = f"trigger={trigger}; {summary}; live root={live_root.hex()[:16]} pinned root={pin.signed_root.hex()[:16]}"
    store.append_audit(server_name, None, "verdict_drift", detail)
    blocked = {change.tool: change.kind for change in changes}
    return DriftReport(server_name, Verdict.DRIFT, detail, changes, blocked)


def word_diff(old: str, new: str) -> str:
    """Word-level diff as `[-removed-] {+added+}`; "" when the words are identical.

    Non-printing characters (zero-width spaces, tag characters, controls) are
    shown as \\u{...} escapes so hidden text is visible in the log.
    """
    before, after = old.split(), new.split()
    matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
    parts: list[str] = []
    changed = False
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op == "equal":
            parts.append(" ".join(before[i1:i2]))
            continue
        changed = True
        if i2 > i1:
            parts.append("[-" + " ".join(before[i1:i2]) + "-]")
        if j2 > j1:
            parts.append("{+" + " ".join(after[j1:j2]) + "+}")
    if not changed:
        return ""
    return "".join(ch if ch.isprintable() else f"\\u{{{ord(ch):04x}}}" for ch in " ".join(parts))


def _describe_modification(old: str, new: str) -> str:
    # description_text in trust.db is display-only: it is not covered by the
    # signature (the leaf hash is), so it must never drive a trust decision.
    if old == new:
        return "(description unchanged; inputSchema or outputSchema changed)"
    return word_diff(old, new) or "(whitespace-only change to the description)"


def _set_status(store: TrustStore, server: str, current: str, tool: str, new: str, reason: str = "") -> None:
    """Change a tool's status, auditing only real transitions so repeated checks do not spam the log."""
    if current == new:
        return
    store.set_status(server, tool, new)
    event = {"active": "tool_reactivated", "suspended": "tool_suspended"}[new]
    store.append_audit(server, tool, event, reason or f"{current} -> {new}: live definition matches the signed pin")


def _tampered(store: TrustStore, server: str, live_leaves: dict[str, bytes], trigger: str, reason: str) -> DriftReport:
    # Fail closed: without a trustworthy record we cannot tell which tools were
    # approved, so every tool from this server is blocked. trust.db statuses
    # are left alone; the record is not trusted enough to write through.
    detail = f"trigger={trigger}; {reason}; blocking all {len(live_leaves)} tools from this server"
    store.append_audit(server, None, "verdict_tampered", detail)
    return DriftReport(server, Verdict.TAMPERED, detail, blocked={name: "tampered" for name in live_leaves})
