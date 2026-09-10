"""Canonical JSON and per-tool leaf hashes.

A server can send the same tool definition with keys in a different order or
with different whitespace. Hashing raw JSON text would call that drift on every
reconnect, so we hash a canonical form instead (RFC 8785 style):

  - object keys sorted recursively (by UTF-16 code units, as RFC 8785 says)
  - no insignificant whitespace
  - UTF-8 output
  - every string VALUE normalized to Unicode NFKC first

NFKC folds compatibility variants (fullwidth letters, ligatures) together, so
those are not drift. Invisible characters such as zero-width spaces or Unicode
tag characters survive NFKC, so hiding text with them still changes the hash.

Object keys are not NFKC-normalized: folding could merge two distinct keys.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from typing import Any

# The only fields that define a tool for pinning purposes. Everything else
# (title, annotations, icons, _meta, ...) is ignored.
HASHED_FIELDS = ("name", "description", "inputSchema", "outputSchema")


def canonicalize(value: Any) -> bytes:
    """Canonical UTF-8 JSON bytes for a JSON-compatible value."""
    return _encode(value).encode("utf-8")


def leaf_hash(tool: dict[str, Any]) -> bytes:
    """SHA-256 over the canonical form of a tool's name, description, inputSchema, outputSchema.

    `tool` uses wire (camelCase) keys, e.g. `Tool.model_dump(by_alias=True, mode="json")`.
    A missing field hashes as null.
    """
    subset = {field: tool.get(field) for field in HASHED_FIELDS}
    if not isinstance(subset["name"], str):
        raise ValueError("tool has no string 'name'")
    return hashlib.sha256(canonicalize(subset)).digest()


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _encode_float(value)
    if isinstance(value, str):
        return _encode_string(unicodedata.normalize("NFKC", value))
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings")
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_encode_string(k)}:{_encode(v)}" for k, v in items) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    raise TypeError(f"not JSON-compatible: {type(value).__name__}")


def _encode_string(text: str) -> str:
    # ensure_ascii=False escapes exactly what RFC 8785 escapes: quote, backslash,
    # and control characters (\b \f \n \r \t, others as lowercase \u00xx).
    return json.dumps(text, ensure_ascii=False)


def _encode_float(value: float) -> str:
    # JSON has one number type, so 1.0 and 1 must canonicalize identically.
    # This matches RFC 8785 for integral values and ordinary decimals; it is not
    # a full ECMAScript number formatter (e.g. exponent spelling of 1e-07).
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity are not valid JSON")
    if value.is_integer() and abs(value) < 2**53:
        return str(int(value))
    return repr(value)
