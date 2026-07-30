"""Round 10: the canonical write-side walks are bounded, on every interpreter.

Scope note, because this file's own claim was once wider than its sweep: what is
fixed here is ``_canon._jsonable``, ``_canon_redact._redact`` and
``_jsonsafe.json_safe``. ``TOLERATED_COMPREHENSION_RECURSION`` below names the
walks elsewhere in the package that are still instances of this same class, with
the measured divergence for each, and the structural sweep now covers every
module so a *new* one cannot be added silently.

The defect this file pins is not "a deep value crashes" but "*where* it crashes
depends on the interpreter". ``_canon._jsonable`` recursed with no bound, and
before 3.12 its dict comprehension got a frame of its own (PEP 709 inlined
comprehensions in 3.12), so identical input crossed the 1000-frame limit at ~495
levels on 3.11 and ~990 on 3.12+. A 600-deep step therefore recorded cleanly and
refused cleanly at save on 3.12 while raising an uncaught ``RecursionError`` from
``Run.add_step`` on 3.11 — the declared support floor and three CI legs.

So these tests assert interpreter-*independence*, and they assert it structurally
rather than by observing one depth: the frame cost per nesting level, the single
explicit bound both walks share, and its relation to the reader's own bound. A
test that only checked "depth 600 refuses at save" would pass on 3.12 with the
bug in place, which is exactly how this reached a release candidate.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import sys
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine._canon import MAX_CANONICAL_DEPTH, _canonical_bytes, _jsonable, _redact
from opentine._graph_types import Step
from opentine._jsonsafe import json_safe
from opentine.kernel import KernelError, validate_json_shape
from opentine.repo import Repo

#: The reader's bound, ``kernel.validate_json_shape``. Duplicated deliberately:
#: if someone moves it, this file should fail and be re-reasoned about.
READER_MAX_DEPTH = 512

PACKAGE = Path(__file__).resolve().parents[1] / "opentine"

#: Functions that still recurse inside a comprehension, and why each is tolerated
#: for this release. Measured maxima, 3.11 vs 3.12, dict chain unless noted:
#:
#: * ``trace/_otel_values.py::_any_value`` — bounded at ``_MAX_DEPTH = 100``, like
#:   ``json_safe``: the cap is reached several times over before either frame
#:   budget, so the extra frame cannot change an outcome. Safe as written.
#: * ``harnesses/_types.py::_jsonable`` — 497 vs 996, unbounded, and public via
#:   ``opentine.harnesses.base``. A harness result nested 500 deep is recorded on
#:   3.12+ and raises an uncaught ``RecursionError`` on the support floor.
#: * ``redaction.py::redact_value`` — list chain 498 vs 996 (its dict branch is
#:   already a statement loop). It runs immediately after the now-bounded
#:   ``_redact`` on the v3 write path, so the bound below is not the boundary
#:   there.
#: * ``billing/_immutable.py::freeze``/``thaw`` — 496 vs 995, unbounded: a rate
#:   card whose catalog reader admits it (depth <= 512) loads on 3.12 and not on
#:   3.11.
#: * ``kernel.py::_encode`` — 330 vs 496, the worst of the four, because on 3.11 a
#:   C call spends from the same recursion budget as a Python frame while 3.12
#:   gave C its own. ``Repo.put`` stores an ``event`` nested 400 deep on 3.12 and
#:   refuses it on 3.11, and an object stored on 3.12 at that depth cannot be read
#:   back on 3.11 at all.
#:
#: Those four are their modules' to fix. Entries here are permission, not
#: obligation: a fix landing elsewhere must not fail this test, but a *new* site
#: anywhere under ``opentine/`` must.
TOLERATED_COMPREHENSION_RECURSION = {
    ("billing/_immutable.py", "freeze"),
    ("billing/_immutable.py", "thaw"),
    ("harnesses/_types.py", "_jsonable"),
    ("kernel.py", "_encode"),
    ("redaction.py", "redact_value"),
    ("trace/_otel_values.py", "_any_value"),
}


def nest(levels: int, leaf: object = 1) -> object:
    """``leaf`` inside exactly ``levels`` nested objects — the bound's own unit."""
    value: object = leaf
    for _ in range(levels):
        value = {"n": value}
    return value


def nest_lists(levels: int) -> object:
    value: object = 1
    for _ in range(levels):
        value = [value]
    return value


@dataclasses.dataclass
class _Node:
    """A recursive dataclass — the shape whose conversion is not a plain mapping."""

    child: object = None


def nest_dataclasses(levels: int, leaf: object = 1) -> object:
    value: object = leaf
    for _ in range(levels):
        value = _Node(child=value)
    return value


class _ReprProbe:
    """Records the Python frame depth at which ``_jsonable`` reaches a leaf."""

    frames = 0

    def __repr__(self) -> str:
        _ReprProbe.frames = len(inspect.stack(0))
        return "leaf"


class _KeyProbe(str):
    """Records the frame depth at which ``_redact`` reaches a leaf mapping."""

    frames = 0

    def __str__(self) -> str:
        _KeyProbe.frames = len(inspect.stack(0))
        return "k"


def test_each_write_side_walk_costs_exactly_one_frame_per_nesting_level():
    # The mechanism, measured rather than assumed. Two frames per level on the
    # support floor and one everywhere else is what made the failure depth differ
    # 2x across the matrix; a comprehension anywhere on these paths brings it
    # back, so the cost is pinned as an equality, not a bound.
    for probe, walk, build in (
        (_ReprProbe, _jsonable, lambda n: nest(n, _ReprProbe())),
        (_KeyProbe, _redact, lambda n: nest(n, {_KeyProbe("k"): 1})),
        # A dataclass is a nesting level too, and converting one by handing a
        # mapping of its fields back to the walk cost two frames while counting
        # one — so the bound was unreachable and a chain of them crashed.
        (_ReprProbe, _jsonable, lambda n: nest_dataclasses(n, _ReprProbe())),
    ):
        walk(build(40))
        shallow = probe.frames
        walk(build(140))
        per_level = (probe.frames - shallow) / 100
        assert per_level == 1, (
            f"{walk.__name__} costs {per_level} frames per nesting level on "
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )


def test_no_walk_over_caller_data_recurses_inside_a_comprehension():
    # The 3.11-only frame is the comprehension's, so the rule that keeps the
    # matrix aligned is structural: recursion happens in statements, never
    # inside a comprehension whose frame pre-3.12 interpreters do not inline.
    # Swept over the whole package on purpose. Scoped to the modules a fix
    # happened to edit, this test passed while four siblings of the very class it
    # names were live — including one that makes a repository written on 3.12
    # unreadable on 3.11.
    found: set[tuple[str, str]] = set()
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            comprehensions = [
                item
                for item in ast.walk(node)
                if isinstance(item, (ast.DictComp, ast.ListComp, ast.SetComp, ast.GeneratorExp))
            ]
            for comprehension in comprehensions:
                calls = [
                    item.func.id
                    for item in ast.walk(comprehension)
                    if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
                ]
                if node.name in calls:
                    found.add((path.relative_to(PACKAGE).as_posix(), node.name))
    assert found <= TOLERATED_COMPREHENSION_RECURSION, (
        "recursion inside a comprehension costs an extra frame per nesting level "
        "before 3.12, which makes the depth at which the walk fails depend on the "
        f"interpreter: {sorted(found - TOLERATED_COMPREHENSION_RECURSION)}"
    )
    # The modules this round owns must be clean, not merely tolerated.
    assert not {name for name, _ in found} & {"_canon.py", "_canon_redact.py", "_jsonsafe.py"}


def test_the_shared_bound_sits_between_the_reader_and_the_frame_budget():
    # Two independent jobs, one number. It must exceed the reader's bound, or a
    # run this build can load back would be unwritable; and it must stay far
    # enough below the interpreter's frame budget that the walks, the stdlib
    # encoder used by save_run and the caller's own stack all fit at once.
    assert MAX_CANONICAL_DEPTH > READER_MAX_DEPTH
    # 128 frames for the caller's own stack: the deepest measured real save path
    # (Repo.put_run) enters the encoder 20 frames deep, pytest here 33.
    assert MAX_CANONICAL_DEPTH + 128 + len(inspect.stack(0)) <= 1000

    deep = nest(MAX_CANONICAL_DEPTH)
    assert _jsonable(deep) == json.loads(_canonical_bytes(deep))
    assert _redact(deep) == deep
    # save_run's own encoder, the widest stdlib consumer on the write path: on
    # 3.11 it is the Python (generator) encoder and dies at ~992 frames.
    assert json.dumps(deep, indent=2, sort_keys=True, allow_nan=False)
    for walk in (_jsonable, _redact):
        with pytest.raises(ValueError, match="nesting or structure"):
            walk(nest(MAX_CANONICAL_DEPTH + 1))


def test_a_value_too_deep_to_walk_is_refused_the_same_way_at_any_shape():
    # Lists, tuples and dicts share one bound: the list branch used to be the
    # remaining comprehension, so a 600-deep list refused on 3.12 and crashed on
    # 3.11 after the dict branch was already fixed.
    for build in (nest, nest_lists, lambda n: (nest_lists(n),)):
        for walk in (_jsonable, _redact):
            with pytest.raises(ValueError, match="nesting or structure"):
                walk(build(MAX_CANONICAL_DEPTH + 8))


def test_a_cyclic_container_is_refused_instead_of_exhausting_the_stack():
    # A self-referential container is infinitely deep, so the depth bound is also
    # what turns the one crash a caller can trigger with *shallow* data into a
    # refusal. (json_safe reports cycles by name; these two walks predate it.)
    cyclic_dict: dict[str, object] = {}
    cyclic_dict["self"] = cyclic_dict
    cyclic_list: list[object] = []
    cyclic_list.append(cyclic_list)
    for walk in (_jsonable, _redact):
        for value in (cyclic_dict, cyclic_list):
            with pytest.raises(ValueError, match="nesting or structure"):
                walk(value)


def test_a_dataclass_wrapping_a_deep_value_is_walked_not_deep_copied():
    # Through 3.12 asdict() deep-copies every nested container, and deepcopy's own
    # unbounded recursion died at ~495 levels — on 3.12 too, where the plain-dict
    # walk was fine, and not on 3.13+, where asdict stopped copying them. A third
    # boundary. The canonical bytes must not change with the traversal.
    @dataclasses.dataclass
    class Wrap:
        payload: object
        label: str = "w"

    deep = nest(600)
    assert _jsonable(Wrap(payload=deep)) == {"label": "w", "payload": _jsonable(deep)}

    step = Step(
        id="s",
        parent_ids=["p"],
        kind=StepKind.tool,
        inputs={"b": [1, {"c": 2}], "a": ("x",)},
        outputs={"ok": True},
    )
    assert _canonical_bytes(step) == _canonical_bytes(dataclasses.asdict(step))
    with pytest.raises(ValueError, match="nesting or structure"):
        _jsonable(Wrap(payload=nest(MAX_CANONICAL_DEPTH + 1)))

    # A *chain* of dataclasses is bounded by the same number, and refused rather
    # than crashed: nothing a reader would accept (depth <= 512) may be unwritable,
    # so the chain has to reach the bound before the frame budget on every
    # interpreter. Recording one just inside the reader's bound must still work.
    assert _jsonable(nest_dataclasses(READER_MAX_DEPTH - 1)) == json.loads(
        _canonical_bytes(nest_dataclasses(READER_MAX_DEPTH - 1))
    )
    with pytest.raises(ValueError, match="nesting or structure"):
        _jsonable(nest_dataclasses(MAX_CANONICAL_DEPTH + 1))
    run = Run(id="dataclass-chain")
    with pytest.raises(ValueError, match="nesting or structure"):
        run.add_step(StepKind.tool, {"a": nest_dataclasses(MAX_CANONICAL_DEPTH + 1)}, {})


def test_a_run_deep_enough_to_load_back_saves_on_every_interpreter(tmp_path):
    # The floor's real regression: this artifact is inside every reader bound, so
    # 3.12 saved and loaded it while 3.11 could not write it at all. The reader
    # decides the boundary, and both sides of it must now agree everywhere.
    loadable = Run(id="loadable")
    loadable.manifest["api_response"] = nest(READER_MAX_DEPTH - 4)
    path = loadable.save(tmp_path / "loadable.tine")
    validate_json_shape(path.read_bytes())
    assert Run.load(path).manifest["api_response"] == nest(READER_MAX_DEPTH - 4)

    unloadable = Run(id="unloadable")
    unloadable.manifest["api_response"] = nest(READER_MAX_DEPTH + 1)
    with pytest.raises(ValueError, match="nesting or structure"):
        unloadable.save(tmp_path / "unloadable.tine")
    assert not (tmp_path / "unloadable.tine").exists()
    with pytest.raises(KernelError):
        validate_json_shape(json.dumps({"manifest": nest(READER_MAX_DEPTH + 1)}))


def test_recording_a_deep_step_never_raises_where_saving_it_would(tmp_path):
    # Refusal belongs at save, where the run is still in memory and the caller can
    # flatten the value; add_step must record anything the walks can encode. On
    # 3.11 this lost the step to a RecursionError with a 350 KB traceback.
    run = Run(id="deep")
    step = run.add_step(StepKind.tool, {"api_response": nest(600)}, {"ok": True})
    assert run.get_step(step.id) is step
    assert step.inputs["api_response"] == nest(600)
    with pytest.raises(ValueError, match="nesting or structure"):
        run.save(tmp_path / "deep.tine")
    assert not (tmp_path / "deep.tine").exists()

    beyond = Run(id="beyond")
    with pytest.raises(ValueError, match="nesting or structure"):
        beyond.add_step(StepKind.tool, {"a": nest(MAX_CANONICAL_DEPTH + 1)}, {})
    assert beyond.steps == []


def test_repository_put_refuses_a_payload_it_cannot_walk(tmp_path):
    # Repo.put does not pass its payload through json_safe, so the redaction walk
    # is the entrance to the v3 store as well: unbounded it raised RecursionError
    # on *every* interpreter, this one not being 3.11-specific at all.
    repo = Repo.init(tmp_path / "repo")
    for payload in (nest(MAX_CANONICAL_DEPTH + 1), {"a": nest_lists(MAX_CANONICAL_DEPTH + 1)}):
        with pytest.raises(ValueError, match="nesting or structure"):
            repo.put("event", payload)
    assert repo.put("event", {"ok": True})


def test_json_safe_keeps_a_bound_reached_long_before_any_frame_budget():
    # The import path's walk is bounded by truncation instead of refusal, which is
    # deliberate (untrusted trace data must import, not fail). What matters for
    # this class is that its bound is reached first on every interpreter, so
    # raising it later cannot silently reintroduce a stack-depth-dependent crash.
    for build in (nest, nest_lists):
        coerced = json_safe(build(5000))
        assert "MAX_DEPTH" in json.dumps(coerced)
    source = (PACKAGE / "_jsonsafe.py").read_text(encoding="utf-8")
    caps = [
        int(node.comparators[0].value)
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == "_depth"
        and isinstance(node.comparators[0], ast.Constant)
    ]
    assert caps and max(caps) * 2 < MAX_CANONICAL_DEPTH
