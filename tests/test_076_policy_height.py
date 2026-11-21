"""A long ``a.b.b...`` selection chain is ``policy.parse`` (too tall), as in TS.

The height check must not recurse: a recursion limit hit was mapped to
``policy.steps``, so the signed admission's rule code differed between Python
and TS and depended on the interpreter's stack.
"""

import pytest

from opentine import _policy_lang
from opentine._policy import rule_result


@pytest.mark.parametrize("n", [65, 500, 1000, 1023])
def test_long_selection_chains_are_refused_as_too_tall(n):
    got = rule_result("a" + ".b" * n, {"a": {}})
    assert (got["outcome"], got["code"]) == ("error", "policy.parse")


def test_height_needs_no_stack_for_a_tall_tree():
    tree: tuple = ("ident", "a")
    for _ in range(5000):
        tree = ("sel", tree, "b")
    assert _policy_lang.height(tree) == 5001
