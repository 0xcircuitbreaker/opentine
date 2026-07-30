"""Round-11 audit regressions: the v3 write path's text rule and the loader's shape rule.

Two classes, both found as raw interpreter exceptions on inputs the format
accepts, and both instances of the same asymmetry: a rule the kernel deliberately
does not enforce, assumed rather than checked by the compatibility seam.

TEXT (write side). ``json.loads`` accepts an unpaired ``\\udXXX`` escape -- what
``JSON.stringify`` emits for a string sliced mid-emoji, so any JS/Java MCP server
truncating a streamed response is a producer -- and hands back a str with no UTF-8
spelling. Round 10 closed the ``.tine`` boundary; every leg that reaches the v3
canonical form *without* passing through ``.tine`` still raised a bare
``UnicodeEncodeError`` from inside redaction, naming a codec and a byte offset in
a fragment the caller could not locate. All of them were already fail-closed, so
this is diagnosability: ``Repo.put`` for every object type, ``put_run``'s two raw
prompt blobs, ``Recorder.start``'s two, and every compatibility JSON blob.

SHAPE (read side). ``validate_run_record`` explicitly permits ``manifest.model =
null`` and the kernel constrains only an event's ``usage``/metrics and a run's
``manifests`` and link lists. ``.get("model", {}).get("name")`` and
``dict(value or {})`` rescue *absence* and then crash on a present-but-wrong
shape, so an object ``fsck`` called healthy took out every command at once.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind
from opentine._v3_guards import as_mapping, guarded_redaction
from opentine.kernel import KernelError
from opentine.repository import Repo
from opentine.trace.recorder import Recorder
from opentine.trace.schema import TraceEvent

# Exactly what a JS-side JSON.stringify emits for a string sliced mid-emoji, and
# the well-formed pair it was sliced out of.
LONE = json.loads('{"p": "done \\ud83d"}')["p"]
LONE_LOW = json.loads('{"p": "done \\udc00"}')["p"]
PAIR = json.loads('{"p": "done \\ud83d\\ude00 \\ud83c\\uddfa\\ud83c\\uddf8"}')["p"]


def _repo(tmp_path: Path, name: str = "r") -> Repo:
    return Repo.init(tmp_path / name)


def _event(**extra: object) -> dict[str, object]:
    payload: dict[str, object] = {"kind": "model", "parent_ids": [], "causal_ids": []}
    payload.update(extra)
    return payload


def _refuses(where: str, path: str):
    """A typed, path-bearing refusal -- never a bare codec error."""
    return pytest.raises(ValueError, match=rf"{where} holds an unpaired UTF-16 surrogate at {path}")


# --------------------------------------------------------------------------- text


@pytest.mark.parametrize("text", [LONE, LONE_LOW])
@pytest.mark.parametrize(
    ("object_type", "payload_key"),
    [("event", "text"), ("annotation", "body"), ("run", "note"), ("attestation", "note")],
)
def test_put_names_the_field_path_for_every_object_type(tmp_path, object_type, payload_key, text):
    repo = _repo(tmp_path)
    with _refuses(f"v3 '{object_type}'", payload_key):
        repo.put(object_type, {payload_key: text})
    assert repo.iter_oids() == [] and repo.list_refs() == {}


def test_put_names_an_offending_object_key_as_an_escape(tmp_path):
    # The path itself holds the bad code unit; spelled as its escape so the
    # message this guard exists to produce is not itself unencodable.
    repo = _repo(tmp_path)
    with pytest.raises(ValueError, match=r"surrogate at done \\ud83d \(object key\)"):
        repo.put("event", _event(**{LONE: "x"}))


def test_put_guards_the_unredacted_write_too(tmp_path):
    # redact=False skips redaction entirely, so kernel.canonical_json used to be
    # the only check and reported "nesting or Unicode key is invalid" with no path.
    repo = _repo(tmp_path)
    with _refuses("v3 'event'", "kind"):
        repo.put("event", _event(kind=LONE), redact=False)


def test_put_run_refuses_either_prompt_before_anything_is_written(tmp_path):
    for attribute in ("system_prompt", "user_prompt"):
        repo = _repo(tmp_path, attribute)
        run = Run(id="run-1", status=RunStatus.completed)
        setattr(run, attribute, LONE)
        with _refuses("run prompt", attribute):
            repo.put_run(run, ref="heads/main")
        # The prompts are raw blobs written from inside the payload literal, so an
        # encode there would already have stored the run's events.
        assert repo.iter_oids() == []
        assert repo.read_ref("heads/main") is None


@pytest.mark.parametrize("field", ["prompt", "system"])
def test_recorder_start_refuses_either_prompt_before_anything_is_written(tmp_path, field):
    repo = _repo(tmp_path, field)
    with _refuses("recorder prompt", field):
        Recorder.start(repo, **{field: LONE}, capture=False)
    assert repo.iter_oids() == [] and repo.list_refs() == {}


def test_recorder_append_refuses_recorded_event_text(tmp_path):
    repo = _repo(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    before = repo.read_ref("heads/main")
    event = TraceEvent(
        kind="model",
        timestamp=1.0,
        trace_id="t" * 32,
        span_id="s" * 16,
        attributes={"note": LONE},
    )
    with _refuses("v3 'event'", "attributes.note"):
        recorder.append(event)
    assert repo.read_ref("heads/main") == before


@pytest.mark.parametrize(
    ("mutate", "path"),
    [
        (lambda run: run.add_step(StepKind.model, {"prompt": LONE}, {}), "prompt"),
        (lambda run: run.add_step(StepKind.model, {}, {"content": LONE}), "content"),
        (lambda run: run.manifest.update({"note": LONE}), "note"),
        (
            lambda run: setattr(run, "transcript", [{"role": "user", "content": LONE}]),
            r"messages\[0\].content",
        ),
        (lambda run: setattr(run, "cache", {"key": LONE}), "key"),
        (lambda run: setattr(run, "policies", {"rule": LONE}), "rule"),
    ],
)
def test_every_compatibility_blob_reports_a_path(tmp_path, mutate, path):
    repo = _repo(tmp_path)
    run = Run(id="run-2", status=RunStatus.completed)
    mutate(run)
    with _refuses("step or run JSON", path):
        repo.put_run(run, ref="heads/main")
    assert repo.read_ref("heads/main") is None


@pytest.mark.parametrize("field", ["prompt", "model"])
def test_recorder_fork_refuses_an_override_it_cannot_encode(tmp_path, field):
    # The third raw str.encode() of recorded text in the tree, and the one round 10
    # classified as safe: repository/_fork_state.py writes a *caller-supplied*
    # prompt override as a raw blob, not a string decoded from bytes.
    repo = _repo(tmp_path, field)
    recorder = Recorder.start(repo, capture=False)
    event_id = recorder.append(
        TraceEvent(kind="model", timestamp=1.0, trace_id="t" * 32, span_id="s" * 16)
    )
    with _refuses("fork override", field):
        recorder.fork(event_id, ref="heads/alt", **{field: LONE})
    assert "heads/alt" not in repo.list_refs()
    assert repo.fsck().ok

    forked = recorder.fork(event_id, ref="heads/alt", **{field: PAIR})
    assert repo.read_ref("heads/alt") == forked.run_id and repo.fsck().ok


def test_recorder_start_manifests_report_a_path(tmp_path):
    with _refuses("step or run JSON", "rule"):
        Recorder.start(_repo(tmp_path), policy={"rule": LONE}, capture=False)


def test_the_preflight_mirror_of_put_also_refuses_typed(tmp_path):
    # repository/_migration_preflight._MemoryRepo.put is a second copy of Repo.put;
    # metadata and tags are written through it first. It must not be the one leg
    # that surfaces a codec error (its message is currently the redaction
    # backstop's, which is typed but cannot name the path -- reported, not fixed).
    for mutate in (lambda run: run.metadata.update({"note": LONE}), lambda run: run.add_tag(LONE)):
        repo = _repo(tmp_path, "mirror")
        run = Run(id="run-3", status=RunStatus.completed)
        mutate(run)
        with pytest.raises(ValueError, match="unpaired UTF-16 surrogate"):
            repo.put_run(run)
        assert not isinstance(getattr(repo, "_last", None), UnicodeEncodeError)
        assert repo.iter_oids() == []


def test_a_credential_shaped_field_is_redacted_not_refused_in_both_formats(tmp_path):
    # _redact replaces a secret field's value outright without walking into it, so
    # the surrogate is gone before any encoder sees it and .tine save accepts the
    # run. Guarding before redaction instead of between its two halves would
    # refuse it in v3 only -- the exact write-side asymmetry this release keeps
    # finding. Both formats must agree.
    run = Run(id="run-4", status=RunStatus.completed)
    run.add_step(StepKind.model, {"api_key": LONE}, {})
    artifact = tmp_path / "secret.tine"
    run.save(str(artifact))
    assert Run.load(str(artifact)).steps[0].inputs == {"api_key": "[REDACTED]"}

    repo = _repo(tmp_path)
    repo.put_run(run, ref="heads/main")
    assert repo.load_run("heads/main").steps[0].inputs == {"api_key": "[REDACTED]"}
    assert repo.fsck().ok


@pytest.mark.parametrize("redact", [True, False])
def test_a_self_referential_payload_is_refused_not_walked_forever(tmp_path, redact):
    # The surrogate walk is iterative and carries no cycle detection, so it must
    # sit behind the shared depth bound on *both* paths. Unredacted it did not:
    # canonical_json's immediate refusal became a walk that never returned and a
    # stack that grew until the process died.
    payload = _event()
    payload["self"] = payload
    with pytest.raises(ValueError, match="768-level limit"):
        _repo(tmp_path, f"cycle{redact}").put("event", payload, redact=redact)


def test_guarded_redaction_leaves_raw_blob_bytes_opaque(tmp_path):
    # CESU-8/WTF-8 surrogate bytes in a *blob* are not text: blobs round-trip
    # byte for byte and nothing re-encodes them.
    raw = LONE.encode("utf-8", "surrogatepass")
    repo = _repo(tmp_path)
    assert repo.get(repo.put("blob", raw)).body == raw
    assert guarded_redaction(raw, where="ignored", redact=False) == raw


def test_a_surrogate_pair_survives_the_whole_v3_round_trip(tmp_path):
    run = Run(id="run-5", status=RunStatus.completed)
    run.system_prompt = run.user_prompt = PAIR
    run.manifest["note"] = PAIR
    run.metadata["note"] = PAIR
    run.cache = {PAIR: PAIR}
    run.policies = {"rule": PAIR}
    run.transcript = [{"role": "user", "content": PAIR}]
    run.add_tag("tag-" + PAIR)
    run.add_step(StepKind.model, {"prompt": PAIR}, {"content": PAIR})
    repo = _repo(tmp_path)
    repo.put_run(run, ref="heads/main")
    back = repo.load_run("heads/main")
    assert (back.system_prompt, back.user_prompt) == (PAIR, PAIR)
    assert back.manifest["note"] == PAIR and back.metadata["note"] == PAIR
    assert back.cache == {PAIR: PAIR} and back.policies == {"rule": PAIR}
    assert back.transcript[0]["content"] == PAIR
    assert back.steps[0].inputs["prompt"] == PAIR and back.steps[0].outputs["content"] == PAIR
    assert repo.fsck().ok

    recorder = Recorder.start(repo, prompt=PAIR, system=PAIR, capture=False, ref="heads/live")
    recorder.append(
        TraceEvent(
            kind="model",
            timestamp=1.0,
            trace_id="t" * 32,
            span_id="s" * 16,
            outputs={"content": PAIR},
        )
    )
    assert repo.fsck().ok


# -------------------------------------------------------------------------- shape


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        (None, ""),  # validate_run_record explicitly permits an explicit null here
        (5, ""),
        ("claude-opus-4", ""),
        ([{"name": "x"}], ""),
        ({"other": 1}, ""),
        ({"name": "claude-opus-4"}, "claude-opus-4"),
    ],
)
def test_a_manifest_model_of_any_shape_still_loads(tmp_path, model, expected):
    run = Run(id="run-6", status=RunStatus.completed)
    run.manifest["model"] = model
    repo = _repo(tmp_path, f"m{type(model).__name__}{expected}")
    repo.put_run(run, ref="heads/main")
    loaded = repo.load_run("heads/main")
    assert loaded.model_info == expected
    assert loaded.manifest["model"] == model  # stored verbatim, never laundered


@pytest.mark.parametrize("field", ["tool", "error", "billing"])
@pytest.mark.parametrize("bad", [5, "x", [1], 1.5, True])
def test_an_event_field_the_kernel_never_constrained_still_loads(tmp_path, field, bad):
    repo = _repo(tmp_path, f"{field}{bad!r}")
    event_id = repo.put("event", _event(**{field: bad}))
    run_id = repo.put(
        "run",
        {
            "created_at": 1.0,
            "events": [event_id],
            "manifests": {},
            "roots": [event_id],
            "status": "completed",
            "tips": [event_id],
        },
    )
    repo.update_ref("heads/main", run_id, expected_old=None)
    step = repo.load_run("heads/main").steps[0]
    assert (step.tool_info, step.error, step.billing) == ({}, {}, {})


@pytest.mark.parametrize("bad", ["abc", [1], {"a": 1}, "1e999999999"])
def test_a_nonnumeric_created_at_is_refused_typed_not_by_float(tmp_path, bad):
    repo = _repo(tmp_path, f"c{bad!r}")
    run_id = repo.put(
        "run",
        {"created_at": bad, "events": [], "manifests": {}, "roots": [], "tips": []},
    )
    repo.update_ref("heads/main", run_id, expected_old=None)
    with pytest.raises(KernelError, match="run created_at"):
        repo.load_run("heads/main")


@pytest.mark.parametrize(("stored", "expected"), [(-1.0, -1.0), ("12.5", 12.5), (0, None)])
def test_a_created_at_that_once_loaded_still_loads(tmp_path, stored, expected):
    # A clock reading may be negative (unlike a cost), and a run this build once
    # read must never stop loading -- that would brick it with no way back.
    repo = _repo(tmp_path, f"k{stored!r}")
    run_id = repo.put(
        "run",
        {"created_at": stored, "events": [], "manifests": {}, "roots": [], "tips": []},
    )
    repo.update_ref("heads/main", run_id, expected_old=None)
    loaded = repo.load_run("heads/main")
    if expected is not None:
        assert loaded.created_at == expected


def test_as_mapping_copies_a_mapping_and_replaces_anything_else():
    source = {"a": 1}
    copied = as_mapping(source)
    assert copied == source and copied is not source  # Step mutates what it is given
    for wrong in (None, 5, "x", [1], (), 1.5, True):
        assert as_mapping(wrong) == {}


def test_the_v3_object_store_and_the_tine_writer_refuse_the_same_strings(tmp_path):
    # One rule, both formats: whatever .tine refuses at save, v3 refuses at put.
    for text in (LONE, LONE_LOW):
        run = Run(id="run-7", status=RunStatus.completed)
        run.add_step(StepKind.model, {"prompt": text}, {})
        with pytest.raises(ValueError, match="unpaired UTF-16 surrogate"):
            run.save(str(Path(tempfile.mkdtemp()) / "a.tine"))
        with pytest.raises(ValueError, match="unpaired UTF-16 surrogate"):
            _repo(tmp_path, f"both{text!r}").put_run(run)


# ------------------------------------------------- write-side/read-side symmetry


def _bare_run(repo: Repo, **fields: object) -> str:
    payload: dict[str, object] = {
        "created_at": 1.0,
        "events": [],
        "manifests": {},
        "roots": [],
        "status": "completed",
        "tips": [],
    }
    payload.update(fields)
    run_id = repo.put("run", payload)
    repo.update_ref("heads/main", run_id, expected_old=None)
    return run_id


@pytest.mark.parametrize(
    ("stored", "name"),
    [("abc", "text"), (float("inf"), "inf"), ("1e999999999", "overflow"), ([1], "list")],
)
def test_put_run_refuses_a_created_at_load_run_would_refuse(tmp_path, stored, name):
    # The recurring shape of this release: a rule the reader enforces and the
    # writer assumes. load_run meters created_at, put_run wrote it unchecked, so
    # repo.put_run(run) stored a run whose every later read raised KernelError --
    # a healthy-looking object no command could open, with the ref advanced to it.
    run = Run(id="run-8", status=RunStatus.completed)
    run.created_at = stored
    repo = _repo(tmp_path, name)
    with pytest.raises(KernelError, match="run created_at"):
        repo.put_run(run, ref="heads/main")
    assert repo.iter_oids() == [] and repo.read_ref("heads/main") is None


@pytest.mark.parametrize("stored", [-1.0, 1.5, 1_700_000_000, "12.5"])
def test_a_created_at_the_reader_accepts_is_still_writable(tmp_path, stored):
    # A clock reading may be negative, and a numeric string is what the reader's
    # own meter accepts -- the guard must not narrow what already round-trips,
    # because refusing more at write than the reader refuses bricks a run too.
    run = Run(id="run-9", status=RunStatus.completed)
    run.created_at = stored
    repo = _repo(tmp_path, str(stored))
    repo.put_run(run, ref="heads/main")
    assert repo.load_run("heads/main").created_at == float(stored)
    assert repo.fsck().ok


@pytest.mark.parametrize(
    ("stored", "name"),
    [(5, "int"), ({"name": "x"}, "dict"), ([1], "list"), (True, "bool"), (None, "null")],
)
def test_a_run_level_model_of_any_shape_loads_as_a_string(tmp_path, stored, name):
    # Nothing in v3 constrains run.model, but validate_run_record requires
    # metadata.model_info to be a string -- so `payload.get("model") or ...` handed
    # back a Run the repository itself could no longer export. The raw field is
    # kept verbatim for whoever wrote it; only the derived attribute is typed.
    repo = _repo(tmp_path, name)
    _bare_run(repo, model=stored)
    loaded = repo.load_run("heads/main")
    assert loaded.model_info == ""
    loaded.save(str(tmp_path / f"{name}.tine"))
    assert Run.load(str(tmp_path / f"{name}.tine")).model_info == ""
    assert repo.get(repo.read_ref("heads/main")).payload().get("model") == stored


def test_a_manifest_model_name_that_is_not_a_string_falls_back(tmp_path):
    # The .tine loader already resolves this field with an isinstance check; the
    # two loaders have to mean the same thing by a wrong shape.
    run = Run(id="run-10", status=RunStatus.completed)
    run.manifest["model"] = {"name": 5}
    repo = _repo(tmp_path)
    repo.put_run(run, ref="heads/main")
    loaded = repo.load_run("heads/main")
    assert loaded.model_info == "" and loaded.manifest["model"] == {"name": 5}


@pytest.mark.parametrize(
    ("stored", "name"),
    [(5, "int"), ([1], "list"), ({"a": 1}, "dict"), (True, "bool"), ("", "empty")],
)
def test_a_source_run_id_of_any_shape_loads_as_the_object_id(tmp_path, stored, name):
    # Same class as model above: Run.id is declared str and validate_run_record
    # requires a non-empty one, so a wrong shape here produced an unexportable run.
    repo = _repo(tmp_path, name)
    run_id = _bare_run(repo, source_run_id=stored)
    loaded = repo.load_run("heads/main")
    assert loaded.id == run_id
    loaded.save(str(tmp_path / f"id-{name}.tine"))


def _two_step_run() -> Run:
    run = Run(id="run-11", status=RunStatus.completed)
    run.add_step(StepKind.model, {"prompt": "hi"}, {})
    run.add_step(StepKind.model, {"prompt": "there"}, {})
    return run


@pytest.mark.parametrize("causal", [5, None, "x", (), {"step-1": 5}, {"step-1": None}])
def test_a_causal_map_that_names_no_step_of_this_run_is_treated_as_absent(tmp_path, causal):
    # _v3_causal_ids is opentine's own attribute, but `getattr(run, ..., {}).get(...)`
    # rescued only its absence: any other shape raised AttributeError from the
    # writer, and a per-step copy of the map would have been quadratic instead.
    # These are the *key* side only -- "step-1" matches no generated step id, so the
    # two mapping cases take the same path as absence. That is all this
    # parametrization ever covered; the item shapes it appeared to cover are below.
    run = _two_step_run()
    run._v3_causal_ids = causal
    repo = _repo(tmp_path, f"causal{causal!r}"[:12])
    repo.put_run(run, ref="heads/main")
    loaded = repo.load_run("heads/main")
    assert [step.inputs for step in loaded.steps] == [{"prompt": "hi"}, {"prompt": "there"}]
    assert set(map(tuple, loaded._v3_causal_ids.values())) == {()}  # no edge invented
    assert repo.fsck().ok


def test_a_causal_entry_naming_a_real_step_is_written_as_an_event_link(tmp_path):
    # The path the parametrization above never reached: a key that does match, whose
    # value is remapped from legacy step ids to the event ids just written.
    run = _two_step_run()
    first, second = (step.id for step in run.steps)
    run._v3_causal_ids = {second: [first]}
    repo = _repo(tmp_path, "edge")
    repo.put_run(run, ref="heads/main")
    loaded = repo.load_run("heads/main")
    new_first, new_second = (step.id for step in loaded.steps)
    assert loaded._v3_causal_ids == {new_first: [], new_second: [new_first]}
    assert repo.fsck().ok


@pytest.mark.parametrize(
    ("item", "raised"),
    [(5, TypeError), (1.5, TypeError), (True, TypeError), (b"ab", KeyError)]
    + [("ab", KeyError), ({"a": 1}, KeyError), (["no-such-step"], KeyError)],
)
def test_a_causal_item_of_the_wrong_shape_does_break_the_write_today(tmp_path, item, raised):
    # Pinned as it is, not as it should be. With a key that matches a step,
    # repository/runs.py's `causal = causal_map.get(step.id) or ()` hands the value
    # straight to a comprehension: a non-iterable raises a bare TypeError, and a str
    # or dict is iterated character- or key-wise into a bare KeyError. Both are raw
    # interpreter errors out of put_run on opentine's own private attribute, and
    # neither names the field -- the same class as_mapping/text_field closed
    # elsewhere in this file. Reported as a cross-file need; runs.py is outside the
    # scope of the fix that corrected this test, so this parametrization is what has
    # to change when the leg is guarded (the refusal becomes a ValueError).
    #
    # It does fail closed: the preflight mirror converts the run into memory first,
    # so the raise lands before the real repository is touched.
    run = _two_step_run()
    run._v3_causal_ids = {run.steps[0].id: item}
    repo = _repo(tmp_path, f"item{item!r}"[:12])
    with pytest.raises(raised):
        repo.put_run(run, ref="heads/main")
    assert repo.iter_oids() == [] and repo.read_ref("heads/main") is None


def test_a_causal_edge_pointing_forward_is_refused_before_anything_is_written(tmp_path):
    # Event ids are content addresses, so a causal link can only name a step already
    # converted; a forward or self reference is unrepresentable rather than merely
    # unwritten. It surfaces as a bare KeyError of the unmapped step id today -- the
    # same reported cross-file need as above -- and, like it, writes nothing.
    run = _two_step_run()
    first, second = (step.id for step in run.steps)
    run._v3_causal_ids = {first: [second]}
    repo = _repo(tmp_path, "forward")
    with pytest.raises(KeyError, match=second):
        repo.put_run(run, ref="heads/main")
    assert repo.iter_oids() == [] and repo.read_ref("heads/main") is None


@pytest.mark.parametrize(
    ("provenance", "name"),
    [({"events": 5}, "int"), ({"events": [["a"]]}, "nested"), ({"events": "ab"}, "str")],
)
def test_a_malformed_source_provenance_reuses_nothing(tmp_path, provenance, name):
    # set(payload["events"]) on a non-list raised TypeError, and on a list of lists
    # "unhashable type". Absence and a wrong shape mean the same thing here.
    run = Run(id="run-12", status=RunStatus.completed)
    run.add_step(StepKind.model, {"prompt": "hi"}, {})
    run._v3_source_payload = provenance
    repo = _repo(tmp_path, name)
    repo.put_run(run, ref="heads/main")
    assert repo.fsck().ok and len(repo.load_run("heads/main").steps) == 1
