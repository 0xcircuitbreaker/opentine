"""Small immutable-container helpers for trusted billing records."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from opentine._canon_redact import MAX_CANONICAL_DEPTH

#: Deepest structure ``freeze``/``thaw`` will build, and the bound both refuse past.
#:
#: Deliberately tighter than the shared write-side ``MAX_CANONICAL_DEPTH``, because
#: freezing is not the last thing done to the result. Comparing two frozen values —
#: what the generated ``__eq__`` of a frozen ``RateCard`` does over its ``metadata``
#: — recurses in C through ``_FrozenList.__eq__`` and through ``MappingProxyType``,
#: and on 3.11 a C call spends from the same 1000-unit recursion budget a Python
#: frame does: measured maximum 331 levels there against ~997 on 3.12+. Bounding
#: these walks at 768 would hand back a card that cannot be compared on the support
#: floor, moving the interpreter-dependent ``RecursionError`` from ``freeze`` to
#: ``==`` rather than removing it. Dividing the shared bound by the three units a
#: comparison costs per level keeps *every* operation billing performs on a frozen
#: value — freeze, thaw, ``==``, ``hash``, canonical hashing, ``json.dumps`` —
#: inside the budget on every supported interpreter with >=128 units spare for the
#: caller's own stack, and it re-scales if the shared bound is ever re-tuned. A real
#: rate card's metadata is two or three levels deep, so this refuses nothing a
#: pricing catalog legitimately holds.
MAX_FROZEN_DEPTH = MAX_CANONICAL_DEPTH // 3


def _too_deep() -> ValueError:
    """The single refusal both walks raise, in the shared bound's language."""
    return ValueError(
        f"billing record nesting or structure exceeds the {MAX_FROZEN_DEPTH}-level limit "
        "every supported interpreter can copy and compare; flatten the offending "
        "rate-card, catalog, or usage metadata"
    )


class _FrozenList(tuple):
    """Immutable tuple with list-compatible value equality."""

    def __eq__(self, other: object) -> bool:
        return tuple(self) == tuple(other) if isinstance(other, (list, tuple)) else False

    __hash__ = tuple.__hash__


def freeze(value: Any, _depth: int = 0) -> Any:
    """Defensively copy mappings/sequences into immutable containers.

    Statement loops rather than the comprehensions this used to be: before PEP 709
    a comprehension cost a second frame per nesting level and a generator
    expression costs one on every version, so the depth at which an untrusted
    pricing catalog crashed this walk depended on the interpreter — measured 495
    (mappings) and 330 (the ``_FrozenList`` generator) on 3.11 against 994/497 on
    3.12+. ``PricingCatalog.from_dict`` reaches here with caller data and catches
    ``ValueError`` but not ``RecursionError``, so unbounded it was an uncaught
    crash on the floor and a clean load elsewhere. Cycles land here too: a
    self-referential mapping is infinitely deep.
    """
    if _depth > MAX_FROZEN_DEPTH:
        raise _too_deep()
    if isinstance(value, Mapping):
        frozen: dict[Any, Any] = {}
        for key, item in value.items():
            frozen[key] = freeze(item, _depth + 1)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        items: list[Any] = []
        for item in value:
            items.append(freeze(item, _depth + 1))
        return _FrozenList(items) if isinstance(value, list) else tuple(items)
    return value


def thaw(value: Any, _depth: int = 0) -> Any:
    """Return ordinary JSON-shaped containers for public serialization.

    Bounded like ``freeze`` and for the same reasons. It is reachable with data
    ``freeze`` never saw — ``RateCard.to_dict`` thaws whatever the caller passed as
    ``context_thresholds`` rules — so the check cannot be left to the other half.
    """
    if _depth > MAX_FROZEN_DEPTH:
        raise _too_deep()
    if isinstance(value, Mapping):
        thawed: dict[Any, Any] = {}
        for key, item in value.items():
            thawed[key] = thaw(item, _depth + 1)
        return thawed
    if isinstance(value, tuple):
        items: list[Any] = []
        for item in value:
            items.append(thaw(item, _depth + 1))
        return items
    return value
