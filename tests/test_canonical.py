import json

import pytest

from proxy.canonical import canonicalize, leaf_hash

ADD = {
    "name": "add",
    "description": "Add two integers and return the sum.",
    "inputSchema": {
        "type": "object",
        "properties": {"a": {"type": "integer", "title": "A"}, "b": {"type": "integer", "title": "B"}},
        "required": ["a", "b"],
    },
    "outputSchema": {"type": "object", "properties": {"result": {"type": "integer"}}, "required": ["result"]},
}


def reverse_keys(value):
    if isinstance(value, dict):
        return {key: reverse_keys(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [reverse_keys(item) for item in value]
    return value


def with_description(description):
    return {**ADD, "description": description}


def test_key_order_does_not_matter():
    assert canonicalize({"a": 1, "b": 2}) == canonicalize({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_reordered_keys_and_different_whitespace_give_identical_hash():
    compact = json.dumps(ADD, separators=(",", ":"))
    pretty_reordered = json.dumps(reverse_keys(ADD), indent=4)
    assert compact != pretty_reordered
    assert leaf_hash(json.loads(compact)) == leaf_hash(json.loads(pretty_reordered))


def test_one_character_description_change_changes_hash():
    assert leaf_hash(ADD) != leaf_hash(with_description("Add two integers and return the sum!"))


def test_output_schema_change_changes_hash():
    changed = {**ADD, "outputSchema": {"type": "object", "properties": {"result": {"type": "string"}}}}
    assert leaf_hash(ADD) != leaf_hash(changed)


def test_fields_outside_the_pinned_four_are_ignored():
    decorated = {**ADD, "title": "Adder", "annotations": {"readOnlyHint": True}, "_meta": {"x": 1}}
    assert leaf_hash(ADD) == leaf_hash(decorated)


def test_nfkc_folds_compatibility_variants():
    fullwidth = with_description("Ａdd two integers and return the sum.")  # fullwidth "A"
    assert leaf_hash(ADD) == leaf_hash(fullwidth)


def test_invisible_characters_still_change_hash():
    hidden = with_description("Add two integers​ and return the sum.")  # zero-width space
    assert leaf_hash(ADD) != leaf_hash(hidden)


def test_integral_float_equals_int():
    assert canonicalize({"n": 1.0}) == canonicalize({"n": 1})


def test_strings_are_escaped_like_rfc8785():
    assert canonicalize({"s": 'line\n"q"\\'}) == b'{"s":"line\\n\\"q\\"\\\\"}'


def test_rejects_non_json_values():
    with pytest.raises(ValueError):
        canonicalize({"n": float("nan")})
