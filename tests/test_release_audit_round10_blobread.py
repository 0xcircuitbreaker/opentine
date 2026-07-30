"""Round-10 audit regressions, group blobread: the write side and the read side
of a repository blob must agree, and every container read out of a manifest
must be shape-checked before it is iterated.

Two defects, one shape — a rule enforced on one side and assumed on the other.

1. ``blob_json`` re-parsed body bytes with a bare ``json.loads`` while every
   other body reader in the kernel passes ``parse_int=_parse_int``.
   ``canonical_json`` renders any finite float with ``2**53 <= |v| < 1e21`` as a
   bare *integer* literal (``canonical_json({"t": 1.7e18})`` is
   ``b'{"t":1700000000000000000}'``), so without the hook the reader got a
   Python ``int`` whose re-encoding raised ``KernelError`` — from a line that
   sat outside the reader's own ``try``. An OTel nanosecond timestamp, a wei
   amount or ``time.time() * 1e9`` in any step payload therefore wrote a run
   that ``put_run`` committed, ``fsck`` called healthy and ``heads/main``
   advanced to, and that no ``load_run`` / ``Run.load`` / migrate-then-load
   could ever read — while ``log``, ``search``, ``fork`` and ``pack`` kept
   succeeding, so nothing surfaced the damage. ``_blob_guard``'s docstring
   asserted this fixpoint "holds by construction"; it holds only *with* the
   hook, which is why the two halves now live in one module.

2. ``put_run_manifest`` iterated ``pricing.get("invocations") or []`` with no
   container check, so a truthy non-iterable there raised a bare
   ``TypeError: 'int' object is not iterable`` out of ``repo.put_run`` and
   ``tine migrate-v3``. The same class was live at two more containers in the
   same module: ``put_transcript``'s ``messages`` (bare ``TypeError`` on a
   scalar, and a silent shred of a ``str`` into one turn per character) and
   ``run_origin``'s ``dict(base["manifests"])`` (bare ``TypeError`` on a
   scalar, ``ValueError: dictionary update sequence element #0 has length 1``
   on a ``str``).
"""

from __future__ import annotations

import ast
import json
import math
import pathlib
import random
import struct
import sys

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._blob_guard import guarded_blob_body, guarded_blob_parse
from opentine.kernel import canonical_json
from opentine.repository import Repo
from opentine.repository._run_blobs import blob_json, put_run_manifest, put_transcript
from opentine.trace import Recorder, TraceEvent

# An unmodified JSON tool result: any number in exponent notation with magnitude
# >= 2**53 parses to a Python float, and json_safe passes finite floats through.
OTEL_RESULT = json.loads('{"startTimeUnixNano": 1.7e18, "name": "span"}')

NUMBER_EDGES = [
    0.0,
    -0.0,
    1.5,
    1e-7,
    1e-6,
    5e-324,  # smallest positive subnormal
    2.2250738585072014e-308,  # smallest positive normal
    1e15,
    float(2**53 - 1),
    float(2**53),  # first float canonical_json renders past the int ceiling
    float(2**53 + 2),
    -float(2**53),
    1e16,
    1.5e16,
    -1e17,
    1.7e18,
    1e20,
    9.999999999999999e20,
    1e21,  # canonical_json switches back to exponent form here
    1e22,
    1.7976931348623157e308,
    -1.7976931348623157e308,
]


def _run_with(outputs: dict[str, object], run_id: str = "clock") -> Run:
    run = Run(id=run_id, model_info="m")
    run.add_step(StepKind.tool, {"q": "now"}, outputs)
    run.status = RunStatus.completed
    return run


def _invoke(monkeypatch, *args: str) -> None:
    monkeypatch.setattr(sys, "argv", ["tine", *args])
    cli.main()


# --------------------------------------------------------------------------
# 1. writer -> store -> reader symmetry across the number edges
# --------------------------------------------------------------------------


@pytest.mark.parametrize("value", NUMBER_EDGES, ids=repr)
def test_canonical_body_is_a_reencode_fixpoint_at_every_number_edge(value, tmp_path):
    body = guarded_blob_body({"v": value})
    parsed = guarded_blob_parse(body)
    # The rule blob_json enforces: the bytes are the canonical encoding of what
    # was read back. Before the hook, 2**53 <= |v| < 1e21 failed this outright.
    assert canonical_json(parsed) == body
    assert parsed["v"] == value
    # And through a real repository, not just the pair of functions.
    repo = Repo.init(tmp_path / "r")
    assert blob_json(repo, repo.put("blob", body, redact=False))["v"] == value


def test_writer_reader_symmetry_fuzz_over_finite_floats(tmp_path):
    # The write side does NOT refuse floats it cannot round-trip, because with
    # the reader's hook there are none. That is proven here rather than asserted
    # in a docstring: the same corpus loses 38.6% of its blobs to a hookless
    # reader (15439 of 40024 measured), and none to this one.
    rng = random.Random(20260729)
    checked = 0
    for _ in range(4000):
        pick = rng.randrange(5)
        if pick == 0:  # arbitrary IEEE-754 bit pattern
            value = struct.unpack("<d", rng.randbytes(8))[0]
        elif pick == 1:  # uniform across the whole exponent range
            value = rng.uniform(-1, 1) * 10.0 ** rng.randint(-320, 308)
        elif pick == 2:  # dense inside the 2**53..1e21 trigger band
            value = rng.uniform(9.007199254740992e15, 1e21)
        elif pick == 3:  # integral-valued floats straddling 2**53
            value = float(rng.randint(2**52, 2**56))
        else:  # subnormals and tiny magnitudes
            value = struct.unpack("<d", struct.pack("<Q", rng.randrange(1, 2**52)))[0]
        for candidate in (value, -value):
            if not math.isfinite(candidate):
                continue
            body = guarded_blob_body({"v": candidate, "nested": [{"deep": candidate}]})
            parsed = guarded_blob_parse(body)
            assert canonical_json(parsed) == body, candidate
            assert parsed["v"] == candidate, candidate
            assert parsed["nested"][0]["deep"] == candidate, candidate
            checked += 1
    assert checked > 6000


def test_non_finite_numbers_are_still_refused_at_write():
    # json_safe stringifies them, so they never reach canonical_json as floats.
    for value in (math.inf, -math.inf, math.nan):
        assert guarded_blob_parse(guarded_blob_body({"v": value}))["v"] == str(value)


# --------------------------------------------------------------------------
# 1b. every read surface of a run carrying a large float
# --------------------------------------------------------------------------


def test_put_run_then_load_run_round_trips_an_otel_nanosecond_timestamp(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    result = repo.put_run(_run_with(OTEL_RESULT), ref="heads/main")
    assert repo.fsck().ok
    for loaded in (repo.load_run(result.run_id), repo.load_run("heads/main")):
        assert loaded.steps[0].outputs["startTimeUnixNano"] == 1.7e18
    assert Run.load(tmp_path / "repo").steps[0].outputs["name"] == "span"


def test_fork_and_pack_of_a_large_float_run_stay_readable(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    run = _run_with(OTEL_RESULT)
    result = repo.put_run(run, ref="heads/main")
    forked = repo.fork(result.run_id, result.event_map[run.steps[0].id], ref="heads/f")
    # fork and pack both propagated the unreadable run into new places, so both
    # have to come back readable.
    assert repo.load_run(forked).steps[0].outputs["startTimeUnixNano"] == 1.7e18
    other = Repo.init(tmp_path / "other")
    other.import_pack(repo.pack())
    assert other.load_run(result.run_id).steps[0].outputs["startTimeUnixNano"] == 1.7e18


def test_recorder_append_of_a_large_float_run_loads(tmp_path):
    repo = Repo.init(tmp_path / "trace")
    recorder = Recorder.start(repo, capture=False)
    recorder.append(TraceEvent("tool", 0.0, "t", "s1", outputs={"t_ns": 1.7e18}))
    assert repo.fsck().ok
    assert repo.load_run(recorder.run_id).steps[0].outputs["t_ns"] == 1.7e18


def test_v2_and_v3_accept_the_same_run(tmp_path):
    run = _run_with(OTEL_RESULT)
    artifact = run.save(tmp_path / "clock.tine")
    assert Run.verify_integrity(artifact).ok
    assert Run.load(artifact).steps[0].outputs["startTimeUnixNano"] == 1.7e18
    repo = Repo.init(tmp_path / "migrated")
    result = repo.migrate_v2(artifact, ref="heads/main")
    assert repo.load_run(result.run_id).steps[0].outputs["startTimeUnixNano"] == 1.7e18


def test_repository_written_before_the_reader_fix_is_readable_now(tmp_path):
    # The bytes on disk were always correct; only the reader could not read
    # them. A repository written by a build with the bug must still load.
    repo = Repo.init(tmp_path / "r")
    oid = repo.put("blob", b'{"t_ns":1700000000000000000}', redact=False)
    assert blob_json(repo, oid) == {"t_ns": 1.7e18}


# --------------------------------------------------------------------------
# 1c. the reader's failures are the reader's own typed error
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        b'{"v":1e400}',  # overflows to infinity: canonical_json cannot re-encode
        b'{"v":' + b"9" * 400 + b"}",  # integer literal that demotes to infinity
        b'{"v":NaN}',
        b'{"v":Infinity}',
        b'{"v":' + b"1" * 5000 + b"}",  # exceeds the interpreter int-literal limit
    ],
    ids=["overflow-float", "overflow-int", "nan", "infinity", "huge-digit-run"],
)
def test_unreencodable_bodies_raise_the_readers_own_error(body, tmp_path):
    repo = Repo.init(tmp_path / "r")
    oid = repo.put("blob", body, redact=False)
    # The canonical re-encode used to sit outside the try, so a KernelError from
    # the kernel encoder leaked instead of the reader's documented refusal.
    with pytest.raises(ValueError, match="compatibility JSON blob is malformed"):
        blob_json(repo, oid)


@pytest.mark.parametrize(
    "body",
    [b"[1,2]", b'{"v":1.0}', b'{"b":1,"a":2}', b'{"v":9007199254740993}', b"null"],
    ids=["array", "non-canonical-float", "unsorted-keys", "unrepresentable-int", "null"],
)
def test_non_canonical_and_non_object_bodies_are_still_refused(body, tmp_path):
    repo = Repo.init(tmp_path / "r")
    oid = repo.put("blob", body, redact=False)
    with pytest.raises(ValueError, match="compatibility JSON blob must be a canonical object"):
        blob_json(repo, oid)


# --------------------------------------------------------------------------
# 1d. class guard: no new hookless canonicity reader anywhere in opentine/
# --------------------------------------------------------------------------

# A reader that re-encodes a parsed body with canonical_json and compares it to
# the original bytes MUST parse with the kernel's parse_int hook, or the two
# operations disagree about integer literals. Three sites are allowed to be
# hookless, each because it has no float position at all:
#   kernel.decode / _blob_io.read_verified_blob_prefix -- the object *header*,
#     three fields whose only number is a schema bounded by an explicit
#     ``type is int and 1 <= schema < 2**53`` check, and whose failure already
#     surfaces as the reader's own KernelError;
#   pack.inspect_pack -- the pack manifest, {"objects": [{"data": str, "id":
#     str}], "shallow": [str], "version": 1}, whose canonical re-encode is
#     already wrapped in a try that raises KernelError("invalid pack manifest").
HOOKLESS_CANONICITY_READERS = {
    ("opentine/kernel.py", "decode"),
    ("opentine/repository/_blob_io.py", "read_verified_blob_prefix"),
    ("opentine/repository/pack.py", "inspect_pack"),
}


def _json_load_calls(function: ast.AST) -> list[ast.Call]:
    found = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr in {"load", "loads"} and getattr(node.func.value, "id", "") == "json":
            found.append(node)
    return found


def test_no_hookless_canonicity_reader_outside_the_documented_allowlist():
    root = pathlib.Path(__file__).resolve().parent.parent / "opentine"
    offenders = set()
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            reencodes = any(
                isinstance(call.func, ast.Name) and call.func.id == "canonical_json"
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
            )
            if not reencodes:
                continue
            for call in _json_load_calls(node):
                if not any(keyword.arg == "parse_int" for keyword in call.keywords):
                    relative = path.relative_to(root.parent).as_posix()
                    offenders.add((relative, node.name))
    assert offenders == HOOKLESS_CANONICITY_READERS


def test_the_blob_contract_modules_never_parse_without_the_kernel_hook():
    root = pathlib.Path(__file__).resolve().parent.parent
    for relative in ("opentine/_blob_guard.py", "opentine/repository/_run_blobs.py"):
        tree = ast.parse((root / relative).read_text(encoding="utf-8"))
        for call in _json_load_calls(tree):
            assert any(keyword.arg == "parse_int" for keyword in call.keywords), relative


# --------------------------------------------------------------------------
# 2. every container read out of a manifest is shape-checked
# --------------------------------------------------------------------------

# The crash set was the truthy non-iterables; the rest already wrote through.
INVOCATION_CONTAINERS = [5, 1.5, True, "abc", {"a": 1}, None, 0, "", [], [[1]]]


@pytest.mark.parametrize("shape", INVOCATION_CONTAINERS, ids=repr)
def test_put_run_tolerates_any_pricing_invocations_container(shape, tmp_path):
    run = Run(id="p", model_info="m")
    run.add_step(StepKind.done, {"text": "d"})
    run.manifest["pricing"] = {"invocations": shape}
    repo = Repo.init(tmp_path / "repo")
    result = repo.put_run(run, ref="heads/main")
    # Stored verbatim, exactly as a str/dict/None container already was: a run
    # Run.load accepts must stay writable, and there are no step references to
    # remap in a non-list container.
    stored = repo.load_run(result.run_id).manifest["pricing"]["invocations"]
    assert stored == ([[1]] if shape == [[1]] else shape)


@pytest.mark.parametrize("shape", [5, 1.5, True], ids=repr)
def test_migrate_v3_imports_an_artifact_with_a_scalar_invocations_container(
    shape, monkeypatch, tmp_path, capsys
):
    run = Run(id="p", model_info="m")
    run.add_step(StepKind.done, {"text": "d"})
    run.manifest["pricing"] = {"invocations": shape}
    source = tmp_path / "a.tine"
    run.save(source)
    repo_path = tmp_path / "repo"
    repo = Repo.init(repo_path)
    # Raw TypeError with rc=1 before: TypeError is outside repo_cli's caught set.
    _invoke(monkeypatch, "migrate-v3", str(source), "--repo", str(repo_path), "--ref", "heads/main")
    assert "run_id" in capsys.readouterr().out
    assert repo.fsck().ok
    assert repo.load_run("heads/main").manifest["pricing"]["invocations"] == shape


def test_forking_a_stored_run_with_a_scalar_invocations_container(tmp_path):
    # run_origin re-slices the *stored* pricing blob through _slice_pricing, so
    # the container also has to survive the compatibility-fork and v3-fork paths
    # after put_run stops crashing on it.
    repo = Repo.init(tmp_path / "repo")
    run = Run(id="a", model_info="m")
    run.add_step(StepKind.tool, {"q": 1}, {"ns": 1.7e18})
    run.add_step(StepKind.done, {"text": "d"})
    run.manifest["pricing"] = {"invocations": 5}
    result = repo.put_run(run, ref="heads/main")
    loaded = repo.load_run(result.run_id)
    assert loaded.manifest["pricing"] == {"invocations": 5}
    compat = repo.put_run(loaded.fork(loaded.steps[0].id), ref="heads/f")
    assert repo.load_run(compat.run_id).manifest["pricing"] == {"invocations": 5}
    native = repo.fork(result.run_id, result.event_map[run.steps[0].id], ref="heads/g")
    assert repo.load_run(native).steps[0].outputs["ns"] == 1.7e18


def test_put_run_manifest_still_refuses_unmappable_step_references(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    manifest = {"pricing": {"invocations": [{"step_id": ["oops"]}]}}
    with pytest.raises(ValueError, match="pricing manifest step references must be strings"):
        put_run_manifest(repo, manifest, {})
    manifest = {"pricing": {"invocations": [{"step_id": "nope"}]}}
    with pytest.raises(ValueError, match="pricing manifest references an unknown step"):
        put_run_manifest(repo, manifest, {})


@pytest.mark.parametrize("shape", [5, 1.5, True, "abc", {"a": 1}], ids=repr)
def test_put_transcript_refuses_a_non_list_transcript(shape, tmp_path):
    repo = Repo.init(tmp_path / "repo")
    # "abc" used to write {"messages": ["a", "b", "c"]} -- a silent shred.
    with pytest.raises(ValueError, match="compatibility transcript must be a list"):
        put_transcript(repo, shape, {})
    run = Run(id="t", model_info="m")
    run.add_step(StepKind.done, {"text": "d"})
    run.transcript = shape
    with pytest.raises(ValueError, match="compatibility transcript must be a list"):
        repo.put_run(run)


@pytest.mark.parametrize("shape", [5, 1.5, True, "abc", [1]], ids=repr)
def test_run_origin_refuses_a_non_mapping_fork_base_manifests(shape, tmp_path):
    repo = Repo.init(tmp_path / "repo")
    run = Run(id="a", model_info="m")
    run.add_step(StepKind.tool, {"q": 1}, {"a": 2})
    run.add_step(StepKind.done, {"text": "d"})
    result = repo.put_run(run, ref="heads/main")
    loaded = repo.load_run(result.run_id)
    forked = loaded.fork(loaded.steps[0].id)
    forked._v3_fork_base = {"manifests": shape}
    with pytest.raises(ValueError, match="compatibility fork has malformed v3 provenance"):
        repo.put_run(forked)
    forked._v3_fork_base = {"manifests": {}}
    assert repo.put_run(forked).run_id.startswith("run:sha256:")
