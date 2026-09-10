import hashlib

from proxy.merkle import changed_leaves, merkle_root


def h(text):
    return hashlib.sha256(text.encode()).digest()


def test_root_does_not_depend_on_insertion_order():
    assert merkle_root({"add": h("1"), "multiply": h("2"), "divide": h("3")}) == merkle_root(
        {"divide": h("3"), "add": h("1"), "multiply": h("2")}
    )


def test_swapping_one_leaf_changes_the_root():
    before = {"add": h("1"), "multiply": h("2"), "divide": h("3")}
    after = {**before, "multiply": h("2 changed")}
    assert merkle_root(before) != merkle_root(after)


def test_every_size_gives_a_distinct_deterministic_root():
    roots = [merkle_root({f"t{i}": h(str(i)) for i in range(n)}) for n in range(0, 8)]
    assert len(set(roots)) == len(roots)
    assert roots == [merkle_root({f"t{i}": h(str(i)) for i in range(n)}) for n in range(0, 8)]


def test_changed_leaves_reports_added_removed_modified():
    old = {"add": h("1"), "multiply": h("2"), "divide": h("3")}
    new = {"add": h("1"), "multiply": h("2 changed"), "power": h("4")}
    changes = changed_leaves(old, new)
    assert changes.added == ["power"]
    assert changes.removed == ["divide"]
    assert changes.modified == ["multiply"]


def test_no_changes():
    leaves = {"add": h("1")}
    assert changed_leaves(leaves, dict(leaves)) == ([], [], [])
