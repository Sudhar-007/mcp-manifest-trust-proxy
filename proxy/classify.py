"""Put a tool change in one of four buckets, with a reason.

    COSMETIC     the text changed and no detector fired
    CAPABILITY   the tool is new, or its schema/parameters changed
    CROSS_SERVER the new text names another server's tool
    INSTRUCTION  the new text gives the model an instruction

Highest severity wins: INSTRUCTION > CROSS_SERVER > CAPABILITY > COSMETIC.
An instruction aimed at the model is the most direct hijack, so it outranks a
cross-server name, which outranks a structural change.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from .detect import agent_directed_imperatives, cross_server_refs


class ChangeClass(str, Enum):
    COSMETIC = "COSMETIC"
    CAPABILITY = "CAPABILITY"
    CROSS_SERVER = "CROSS_SERVER"
    INSTRUCTION = "INSTRUCTION"


SEVERITY = {
    ChangeClass.COSMETIC: 1,
    ChangeClass.CAPABILITY: 2,
    ChangeClass.CROSS_SERVER: 3,
    ChangeClass.INSTRUCTION: 4,
}


def classify_change(
    old_tool: dict[str, Any] | None,
    new_tool: dict[str, Any],
    registry: dict[str, list[str]] | None = None,
    self_server: str | None = None,
    definition_changed: bool = False,
) -> tuple[ChangeClass, str]:
    """Classify old -> new. `old_tool` is None for a newly added tool.

    `registry`/`self_server` are what cross_server_refs needs. Set
    `definition_changed` when the caller already knows the definition changed
    but cannot compare the old schema (the trust store keeps hashes, not
    schemas), so an unchanged description means the schema moved.
    """
    new_description = new_tool.get("description") or ""

    imperatives = agent_directed_imperatives(new_description)
    if imperatives:
        return ChangeClass.INSTRUCTION, "; ".join(f.describe() for f in imperatives)

    cross = cross_server_refs(new_description, registry or {}, self_server)
    if cross:
        return ChangeClass.CROSS_SERVER, "; ".join(f.describe() for f in cross)

    if old_tool is None:
        return ChangeClass.CAPABILITY, "new tool added"

    has_old_schema = "inputSchema" in old_tool or "outputSchema" in old_tool
    if has_old_schema and (
        old_tool.get("inputSchema") != new_tool.get("inputSchema")
        or old_tool.get("outputSchema") != new_tool.get("outputSchema")
    ):
        return ChangeClass.CAPABILITY, "input or output schema changed"

    if (old_tool.get("description") or "") != new_description:
        return ChangeClass.COSMETIC, "description text changed, no detector fired"

    if definition_changed:
        return ChangeClass.CAPABILITY, "definition changed with an unchanged description (schema or parameters)"

    return ChangeClass.COSMETIC, "no material change"
