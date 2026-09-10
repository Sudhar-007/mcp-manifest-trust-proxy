"""Merkle root over a server's tool leaf hashes.

Why a Merkle tree rather than one hash over the whole manifest:

  - One hash over everything tells you THAT something changed, never WHICH
    tool. To find out you would have to keep and diff the entire manifest.
    Here each tool is its own leaf, so a mismatch is localized by comparing
    32-byte leaf hashes, and only the tools that actually changed get
    suspended.
  - We still sign a single 32-byte root, so one signature covers the whole
    approved set, and the common "nothing changed" case is one comparison.
  - Re-pinning after a human approves a changed tool is a leaf swap: replace
    that tool's leaf, recompute the root, re-sign. Nothing else is touched.

Construction follows RFC 6962 (Certificate Transparency): leaves are sorted by
tool name, leaf nodes are hashed with a 0x00 prefix and interior nodes with
0x01, so a leaf can never be passed off as an interior node, and odd leaf
counts split at the largest power of two instead of duplicating a leaf.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import NamedTuple

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


class ChangedLeaves(NamedTuple):
    added: list[str]
    removed: list[str]
    modified: list[str]


def merkle_root(leaf_hashes: Mapping[str, bytes]) -> bytes:
    """Root over {tool_name: leaf_hash}, with leaves ordered by tool name."""
    return _tree_hash([leaf_hashes[name] for name in sorted(leaf_hashes)])


def changed_leaves(old: Mapping[str, bytes], new: Mapping[str, bytes]) -> ChangedLeaves:
    """Which tool names were added, removed, or modified between two leaf sets."""
    return ChangedLeaves(
        added=sorted(new.keys() - old.keys()),
        removed=sorted(old.keys() - new.keys()),
        modified=sorted(name for name in old.keys() & new.keys() if old[name] != new[name]),
    )


def _tree_hash(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(LEAF_PREFIX + leaves[0]).digest()
    split = 1 << ((len(leaves) - 1).bit_length() - 1)  # largest power of two below len(leaves)
    return hashlib.sha256(NODE_PREFIX + _tree_hash(leaves[:split]) + _tree_hash(leaves[split:])).digest()
