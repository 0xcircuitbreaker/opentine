"""Round 11: the kernel's canonical encoder has ONE nesting bound, on every interpreter.

``kernel._encode`` used to be bounded by a ``RecursionError`` caught in
``canonical_json``, and both of its joins drove a generator expression, which
costs a Python frame per nesting level on *every* interpreter — plus, before 3.12,
a C call spent from the same budget as a Python frame. So the depth at which the
v3 store stopped accepting an object was a property of the interpreter, not of the
format: measured maxima 330 on 3.11 versus 496 on 3.12/3.13/3.14, while
``validate_json_shape`` — the reader — accepted 512.

That produced two defects a release cannot ship:

1. A cross-interpreter data-portability break. An event written at depth 400 on
   3.12 was UNREADABLE on 3.11: ``Repo.get(oid).payload()`` raised
   ``KernelError('canonical JSON nesting or Unicode key is invalid')`` because the
   read path re-encodes the parsed body to check canonicity. Same repository, same
   bytes, different interpreter, different answer.
2. A writer/reader asymmetry inside the kernel itself: depths 331..511 were
   format-legal per ``validate_json_shape`` and unwritable on the declared support
   floor.

The fix is a bound, not a bigger stack: ``_encode`` refuses past
``MAX_JSON_DEPTH`` — which is now the same name ``validate_json_shape`` reads, so
the two cannot drift apart — and its two container walks are statement loops, so
the walk costs exactly one frame per level everywhere and the bound is always
reached before any frame budget.

These tests therefore assert interpreter-*independence*, and they assert it as the
SAME boundary everywhere: no test here branches on ``sys.version_info``. A test
that only checked "depth 600 is refused" would have passed on 3.12 with the defect
live, which is how this reached a release candidate.
"""

from __future__ import annotations

import ast
import inspect
import json
import sys
from pathlib import Path

import pytest

from opentine import kernel
from opentine.kernel import (
    MAX_JSON_DEPTH,
    KernelError,
    ObjectEnvelope,
    _encode,
    _number,
    _parse_int,
    canonical_json,
    validate_json_shape,
)
from opentine.repository import Repo

#: The bound's value, duplicated on purpose (round 10's convention): changing the
#: number is a decision that must be made here as well as in the kernel, because
#: it is the depth at which *every* supported interpreter must agree.
EXPECTED_MAX_DEPTH = 512

#: Canonical bytes of the deepest legal dict chain, hashed. One constant for the
#: whole CI matrix: if any interpreter encodes a legal value differently, or the
#: bound moves, this changes.
DEEPEST_CHAIN_SHA = "2556ec76c9adbf2e0768d85d0cbc5456a786fbb7e3a1a28a2f4abb4f88cf60e7"
DEEPEST_CHAIN_OID = "event:sha256:e2cb076c0de58e2b4521e8e6d6be9473d0b893d80d99fc1f2b8cd1832dd4272d"

KERNEL_SOURCE = Path(kernel.__file__)

#: The window the defect made unwritable on the support floor while the reader
#: called it legal: 331 (just past 3.11's old ceiling) .. 512 (the reader's bound).
ASYMMETRIC_WINDOW = (331, 400, 496, 511, 512)


def nest(levels: int, leaf: object = 1) -> object:
    value: object = leaf
    for _ in range(levels):
        value = {"n": value}
    return value


def nest_lists(levels: int, leaf: object = 1) -> object:
    value: object = leaf
    for _ in range(levels):
        value = [value]
    return value


def nest_mixed(levels: int) -> object:
    value: object = 1
    for index in range(levels):
        value = [value] if index % 2 else {"n": value}
    return value


def dict_bytes(levels: int) -> bytes:
    return b'{"n":' * levels + b"1" + b"}" * levels


def stack_depth() -> int:
    frame, count = sys._getframe(), 0
    while frame is not None:
        count += 1
        frame = frame.f_back
    return count


class _Leaf(float):
    """A leaf that reports the frame depth at which ``_encode`` reached it."""

    frames = 0

    def __repr__(self) -> str:
        _Leaf.frames = stack_depth()
        return "1.0"


def encodes(depth: int, build=nest) -> bool:
    try:
        canonical_json(build(depth))
    except BaseException:  # noqa: BLE001 - a RecursionError here is the defect
        return False
    return True


def max_encodable(build=nest, high: int = 4096) -> int:
    low = 1
    assert encodes(low, build)
    assert not encodes(high, build)
    while low + 1 < high:
        middle = (low + high) // 2
        if encodes(middle, build):
            low = middle
        else:
            high = middle
    return low


def test_the_writer_and_the_reader_share_one_nesting_bound():
    # The container defect, not just the instance: before this round the writer's
    # ceiling was an accident of the interpreter's frame budget and the reader's
    # was a literal 512 sitting in another function. One name now, so a future
    # edit cannot move one side only.
    assert MAX_JSON_DEPTH == EXPECTED_MAX_DEPTH

    tree = ast.parse(KERNEL_SOURCE.read_text(encoding="utf-8"))
    assignments = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(getattr(target, "id", "") == "MAX_JSON_DEPTH" for target in node.targets)
    ]
    assert len(assignments) == 1
    stray = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and node.value == EXPECTED_MAX_DEPTH
        and node is not assignments[0].value
    ]
    assert not stray, f"a second hard-coded depth limit at line(s) {[n.lineno for n in stray]}"
    for name in ("_encode", "validate_json_shape"):
        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == name
        )
        names = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)}
        assert "MAX_JSON_DEPTH" in names, f"{name} does not read the shared bound"

    # And they agree in behaviour, not only in source: the deepest value the writer
    # will produce is exactly the deepest the reader will accept.
    assert max_encodable() == MAX_JSON_DEPTH
    validate_json_shape(canonical_json(nest(MAX_JSON_DEPTH)))
    with pytest.raises(KernelError, match="semantic parser limits"):
        validate_json_shape(dict_bytes(MAX_JSON_DEPTH + 1))


def test_max_encodable_depth_is_the_same_number_on_every_interpreter():
    # The measurement that exposed the break: 330 on 3.11, 496 on 3.12+. Asserted
    # as an equality against a constant, so this test means the same thing on every
    # leg of the matrix.
    for build in (nest, nest_lists, nest_mixed, lambda n: (nest_lists(n - 1),)):
        assert max_encodable(build) == MAX_JSON_DEPTH, (
            f"{build} bounds encoding at a different depth on "
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )
    # Everything at or below the bound encodes, including the whole window the
    # floor used to refuse while the reader called it legal.
    for depth in (1, 2, 3, 64, *ASYMMETRIC_WINDOW):
        assert canonical_json(nest(depth)).count(b"{") == depth


def test_canonical_encoding_costs_exactly_one_frame_per_nesting_level():
    # The mechanism behind the divergence, measured rather than assumed: a
    # generator expression gets a frame of its own on every interpreter, and before
    # 3.12 the driving C call spent from the same budget again — 3 frames per level
    # on 3.11 against 2 on 3.12+. Pinned as an equality: at 1 frame per level the
    # explicit bound is always reached first, which is what makes the depth
    # behaviour a property of the format instead of the runtime.
    for build in (nest, nest_lists):
        canonical_json(build(40, _Leaf(1.0)))
        shallow = _Leaf.frames
        canonical_json(build(140, _Leaf(1.0)))
        per_level = (_Leaf.frames - shallow) / 100
        assert per_level == 1, (
            f"canonical encoding costs {per_level} frames per nesting level on "
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )


def test_the_kernel_bound_is_a_depth_check_and_not_a_caught_recursion_error():
    # Structural, because the value alone cannot show which mechanism produced it.
    # Round 10 tolerated this function recursing inside a comprehension; the kernel
    # must now be clean, and no walk over caller data may reintroduce the frame.
    tree = ast.parse(KERNEL_SOURCE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for comprehension in ast.walk(node):
            if not isinstance(
                comprehension, (ast.DictComp, ast.ListComp, ast.SetComp, ast.GeneratorExp)
            ):
                continue
            calls = {
                item.func.id
                for item in ast.walk(comprehension)
                if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
            }
            assert node.name not in calls, (
                f"kernel.{node.name} recurses inside a comprehension at line "
                f"{comprehension.lineno}: an extra frame per nesting level makes the "
                "failure depth interpreter-dependent"
            )
    encode = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_encode"
    )
    assert [argument.arg for argument in encode.args.args] == ["value", "depth"]
    assert any(isinstance(node, ast.Compare) for node in ast.walk(encode))

    # The refusal is raised, not converted from a crash: a caught RecursionError
    # would arrive as ``__cause__``.
    with pytest.raises(KernelError, match="nesting exceeds") as excinfo:
        canonical_json(nest(MAX_JSON_DEPTH + 1))
    assert excinfo.value.__cause__ is None


def test_a_value_deeper_than_the_bound_is_refused_the_same_way_at_any_shape():
    # Dicts, lists, tuples and cycles share one bound, one message and one type,
    # at depths far past both old ceilings (330 and 496) so a partial fix fails.
    cyclic_dict: dict[str, object] = {}
    cyclic_dict["self"] = cyclic_dict
    cyclic_list: list[object] = []
    cyclic_list.append(cyclic_list)
    values = [
        nest(MAX_JSON_DEPTH + 1),
        nest_lists(MAX_JSON_DEPTH + 1),
        nest_mixed(MAX_JSON_DEPTH + 1),
        (nest_lists(MAX_JSON_DEPTH),),
        nest(600),
        nest_lists(5000),
        {"outer": nest(MAX_JSON_DEPTH)},
        cyclic_dict,
        cyclic_list,
    ]
    for value in values:
        with pytest.raises(KernelError, match=f"nesting exceeds {MAX_JSON_DEPTH} levels") as info:
            canonical_json(value)
        # A cycle or an over-deep value is refused by the check, so no interpreter
        # ever unwinds a RecursionError here.
        assert info.value.__cause__ is None
        with pytest.raises(KernelError, match="nesting exceeds"):
            ObjectEnvelope.create("event", value)


def test_every_object_the_store_can_write_can_be_read_back_by_any_interpreter(tmp_path):
    # The portability contract. Each depth in the old asymmetric window was legal
    # to the reader and unwritable on 3.11; depth 400 in particular was written by
    # 3.12 and then unreadable on 3.11, because decode re-encodes to check
    # canonicity. Write, decode, parse and re-encode must all clear the same bound.
    for depth in ASYMMETRIC_WINDOW:
        payload = {"causal_ids": [], "deep": nest(depth - 1), "parent_ids": []}
        envelope = ObjectEnvelope.create("event", payload)
        stored = envelope.encode()
        assert kernel.verify_object(stored, envelope.oid)
        restored = ObjectEnvelope.decode(stored, envelope.oid)
        assert restored.payload() == payload
        assert restored.body == envelope.body

    deepest = nest(MAX_JSON_DEPTH)
    body = canonical_json(deepest)
    assert json.loads(body) == deepest
    assert kernel.hashlib.sha256(body).hexdigest() == DEEPEST_CHAIN_SHA
    assert ObjectEnvelope.create("event", deepest).oid == DEEPEST_CHAIN_OID

    # Nothing writable is unreadable, and nothing unwritable is readable: the body
    # one level past the bound is refused by the reader too, so no interpreter can
    # produce a repository another cannot read.
    header = canonical_json({"encoding": "json", "schema": 1, "type": "event"})
    ObjectEnvelope.decode(header + b"\n" + dict_bytes(MAX_JSON_DEPTH))
    with pytest.raises(KernelError, match="semantic parser limits"):
        ObjectEnvelope.decode(header + b"\n" + dict_bytes(MAX_JSON_DEPTH + 1))

    repo = Repo.init(tmp_path / "repo")
    payload = {"causal_ids": [], "deep": nest(MAX_JSON_DEPTH - 1), "parent_ids": []}
    oid = repo.put("event", payload)
    assert repo.get(oid).payload() == payload
    assert oid in repo.iter_oids()
    with pytest.raises(KernelError, match="nesting exceeds"):
        repo.put("event", {"causal_ids": [], "deep": nest(MAX_JSON_DEPTH), "parent_ids": []})


def test_the_bound_leaves_frame_headroom_for_the_read_and_write_paths():
    # 512 rather than a larger number: the walk must reach the bound with room to
    # spare on the smallest budget in the matrix, and the reader's own recursive
    # descent (json's C scanner, which on 3.11 spends the same budget as Python
    # frames) must clear it too, or reading back would become the new asymmetry.
    assert MAX_JSON_DEPTH + 128 + len(inspect.stack(0)) <= sys.getrecursionlimit()
    body = dict_bytes(MAX_JSON_DEPTH)
    validate_json_shape(body)
    assert json.loads(body) == nest(MAX_JSON_DEPTH)
    assert canonical_json(json.loads(body)) == body
    # The measured deepest real entry into the encoder (Repo.put) is ~10 frames, so
    # a value at the bound encodes from well inside any real call path.
    assert canonical_json(nest(MAX_JSON_DEPTH - 40)) is not None


def test_scalar_encodings_stay_byte_identical_across_interpreters():
    # The two lines this round shed came out of _number, whose output feeds every
    # object id: pinned exactly, including the exponent form, so a shorter
    # implementation can never become a silent rehash of the store.
    assert [_number(value) for value in (0.0, -0.0, 2.5, 1 / 3, 0.1, 1e-6, 1e20)] == [
        "0",
        "0",
        "2.5",
        "0.3333333333333333",
        "0.1",
        "0.000001",
        "100000000000000000000",
    ]
    assert [_number(value) for value in (1e21, -1e21, 1e-7, 5e-324, 6.02e23, 1e-100)] == [
        "1e+21",
        "-1e+21",
        "1e-7",
        "5e-324",
        "6.02e+23",
        "1e-100",
    ]
    assert _number(1.7976931348623157e308) == "1.7976931348623157e+308"
    assert _number(9_007_199_254_740_991) == "9007199254740991"
    for value in (1e21, 1e-7, 5e-324, 6.02e23, 1e-100, 1.7976931348623157e308, 0.1, 1 / 3):
        assert float(_number(value)) == value
        assert float(_number(-value)) == -value
    with pytest.raises(KernelError, match="exceeds 2\\*\\*53-1"):
        _number(9_007_199_254_740_992)
    with pytest.raises(KernelError, match="forbids NaN"):
        _number(float("inf"))
    # The reader's own integer hook, the other place a literal's width decides an
    # outcome: identical on every interpreter, refusal rather than a raw ValueError.
    assert _parse_int("9007199254740991") == 9_007_199_254_740_991
    assert _parse_int("9007199254740992") == 9.007199254740992e15
    with pytest.raises(KernelError, match="integer literal is too large"):
        _parse_int("1" * (sys.get_int_max_str_digits() + 1))


def test_the_bound_applies_to_containers_and_never_to_scalars():
    # The check sits in front of the container branches only: a scalar at the
    # deepest legal level still encodes, and an unsupported type is still named as
    # one rather than being reported as too deep.
    assert canonical_json(nest(MAX_JSON_DEPTH, "leaf")).endswith(b'"leaf"' + b"}" * MAX_JSON_DEPTH)
    assert _encode({}, MAX_JSON_DEPTH - 1) == "{}"
    assert _encode("x", MAX_JSON_DEPTH) == '"x"'
    assert _encode(None, MAX_JSON_DEPTH + 99) == "null"
    with pytest.raises(KernelError, match="unsupported canonical JSON type: set"):
        canonical_json({"a": {1, 2}})
    with pytest.raises(KernelError, match="object keys must be strings"):
        canonical_json(nest(MAX_JSON_DEPTH - 1, {1: "x"}))
