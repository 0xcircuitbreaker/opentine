"""0.26 phase 6: format v4 is the default writer; older formats are opt-in.

Plain saves, signatures and new repositories are v4; ``OPENTINE_FORMAT=2`` (or
``tine --format 2``) keeps the deprecated writers with one warning. Explicit
writes refuse what v4 cannot hold; recorders stringify it and warn. Bundles
carry ``tine-sig/3`` sidecar blocks. No golden fixture is ever rewritten by a read.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import threading
import time
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, _bundle, _format_v4, cli
from opentine._artifact_io import read_artifact_json
from opentine._format_v4 import FORMAT_ENV, is_v4_artifact
from opentine.autosave import Autosaver
from opentine.repo import Repo
from opentine.repository._config import config_lock, mark_v4, read_config
from opentine.repository._sig_sidecar import signatures_for
from opentine.trace._record_event import WARNINGS_KEY
from opentine.trace.recorder import Recorder
from opentine.trace.schema import TraceEvent

FIXTURES = Path(__file__).parent / "fixtures"
HMAC = b"0123456789abcdef0123456789abcdef"
WIDE = 2**60


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    for name in ("OPENTINE_OUTPUT", FORMAT_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(_format_v4, "_WARNED", [])
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _run(run_id: str = "default-v4", **extra) -> Run:
    run = Run(id=run_id, model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.think, {"text": "thinking", **extra}, {"a": [1, 0.5]})
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    return run


def _config(path: Path) -> dict:
    return json.loads((path / ".tine" / "config.json").read_bytes())


def _tine(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, captured.out + captured.err


# --------------------------------------------------------------------------- #
def test_plain_save_writes_v4(room, capsys):
    path = _run().save(room / "plain.tine")
    assert is_v4_artifact(read_artifact_json(path))
    assert Run.verify_integrity(path).ok and Run.load(path).id == "default-v4"
    assert "deprecated" not in capsys.readouterr().err


@pytest.mark.parametrize("value", ["2", "3"])
def test_format_2_writes_v2_with_one_warning(room, monkeypatch, capsys, value):
    monkeypatch.setenv(FORMAT_ENV, value)
    first = _run().save(room / "a.tine")
    _run("b").save(room / "b.tine")
    assert read_artifact_json(first)["format_version"] == 2
    err = capsys.readouterr().err
    assert err.count("deprecated") == 1 and "format v5" in err


def test_tine_format_2_flag_pins_the_legacy_writer(room, capsys):
    _run().save(room / "src.tine")
    step = Run.load(room / "src.tine").steps[0].id
    argv = ("--format", "2", "fork", "src.tine", "--from-step", step, "--save", "f.tine")
    code, out = _tine(capsys, *argv)
    assert code == 0, out
    assert read_artifact_json(room / "f.tine")["format_version"] == 2
    assert "deprecated" in out
    assert _format_v4.v4_requested()  # the pin ends with the command
    code, out = _tine(capsys, "fork", "src.tine", "--from-step", step, "--save", "g.tine")
    assert code == 0 and is_v4_artifact(read_artifact_json(room / "g.tine"))


def test_signing_defaults_to_tine_sig_3(room):
    path = _run().save(room / "s.tine", sign_key=HMAC, key_id="k")
    block = read_artifact_json(path)["signatures"][0]
    assert block["scheme"] == "tine-sig/3"
    assert Run.verify_signature(path, hmac_key=HMAC).state == "verified"


def test_a_new_repository_is_object_format_4(room, monkeypatch):
    repo = Repo.init(room / "r")
    config = _config(room / "r")
    assert config["objects"] == 4 and "format" not in config and config["min_reader"] == "0.26.0"
    oid = repo.put_run(_run(), ref="heads/main").run_id
    assert Repo.open(room / "r").fsck().ok and repo.load_run(oid).id == "default-v4"
    monkeypatch.setenv(FORMAT_ENV, "3")
    Repo.init(room / "old")
    assert _config(room / "old")["format"] == 3  # the deprecated legacy descriptor


def test_migrate_defaults_to_v4(room, capsys):
    with _format_v4.write_format(2):
        _run().save(room / "src.tine")
    code, out = _tine(capsys, "migrate", "src.tine", "--save", "up.tine")
    assert code == 0, out
    assert is_v4_artifact(read_artifact_json(room / "up.tine"))
    assert read_artifact_json(room / "src.tine")["format_version"] == 2  # untouched


# --------------------------------------------------------------------------- #
def test_an_explicit_write_with_a_bigint_refuses(room):
    with pytest.raises(ValueError, match=r"inputs\.n .*2\*\*53-1"):
        _run(n=WIDE).save(room / "big.tine")
    assert not (room / "big.tine").exists()
    repo = Repo.init(room / "r")
    with pytest.raises(ValueError, match=r"2\*\*53-1"):
        repo.put_run(_run(n=WIDE))
    assert not repo.iter_oids()
    infinite = _run()
    infinite.steps[0].inputs["x"] = float("inf")  # add_step itself refuses one
    with pytest.raises(ValueError, match="cannot represent"):
        infinite.save(room / "inf.tine")


def test_a_recorder_with_a_bigint_stringifies_it_and_warns(room):
    run = _run(n=WIDE)
    run.steps[0].inputs["x"] = float("nan")  # add_step itself refuses one
    path = run.save(room / "rec.tine", lenient=True)
    loaded = Run.load(path)
    step = loaded.steps[0]
    assert step.inputs["n"] == str(WIDE) and step.inputs["x"] == "nan"  # exact, not rounded
    warnings = loaded.metadata["warnings"]
    assert any(".inputs.n:" in w for w in warnings) and any(".inputs.x:" in w for w in warnings)
    autosaved = _run("auto", n=WIDE)
    Autosaver(room / "auto.tine").flush(autosaved)  # the autosaver's final write
    assert Run.load(room / "auto.tine").steps[0].inputs["n"] == str(WIDE)
    repo = Repo.init(room / "r")
    lenient = _run("into-repo", n=WIDE)
    lenient.save(room / "r", lenient=True)
    assert repo.load_run("heads/main").steps[0].inputs["n"] == str(WIDE)


def test_cli_record_marks_its_run_lenient():
    from opentine._cli_record import build_run

    run = build_run(["echo"], [], 0)
    assert run.__dict__.get("_v4_lenient") is True


def test_a_trace_recorder_with_a_bigint_warns_instead_of_crashing(room):
    repo = Repo.init(room / "r")
    recorder = Recorder.start(repo, prompt="p")
    event = TraceEvent(
        kind="model",
        timestamp=1.0,
        trace_id="t",
        span_id="s",
        inputs={"id": WIDE},
        usage={"input": 3, "odd": WIDE},
    )
    event_id = recorder.append(event)
    payload = repo.get(event_id).payload()
    warned = payload["attributes"][WARNINGS_KEY]
    assert any(w.startswith("inputs.id:") for w in warned)
    assert any(w.startswith("usage.odd:") for w in warned)
    assert payload["attributes"]["usage.odd"] == str(WIDE)
    assert repo.fsck().ok


# --------------------------------------------------------------------------- #
def test_a_bundle_carries_signatures(room, capsys):
    run = _run()
    run.add_tag("keep")
    run.save(room / "s.tine", sign_key=HMAC)
    original = read_artifact_json(room / "s.tine")
    Repo.init(room / "a")
    assert _tine(capsys, "import", "s.tine", "--repo", "a")[0] == 0
    source = Repo.open(room / "a")
    data = _bundle.create(source, ["heads/main"])
    assert _bundle.verify(data).signatures  # in the manifest, not the pack
    target = Repo.init(room / "b")
    _bundle.unbundle(target, data, "a")
    head = original["annotations"][-1]["id"]
    assert signatures_for(target, original["root"], head) == original["signatures"]
    argv = ("migrate", "remotes/a/main", "--to", "v4", "--repo", "b", "-o", "back.tine")
    assert _tine(capsys, *argv)[0] == 0
    assert read_artifact_json(room / "back.tine") == original
    # A bundle without sidecar blocks keeps the 0.25 manifest shape exactly.
    plain = Repo.init(room / "c")
    plain.put_run(_run("plain"), ref="heads/main")
    assert not _bundle.verify(_bundle.create(plain, ["heads/main"])).signatures


def test_bundle_signature_entries_are_shape_checked(room, capsys):
    from opentine._bundle_sigs import check

    _run().save(room / "s.tine", sign_key=HMAC)
    Repo.init(room / "a")
    assert _tine(capsys, "import", "s.tine", "--repo", "a")[0] == 0
    signatures = _bundle.verify(_bundle.create(Repo.open(room / "a"), ["heads/main"])).signatures
    ((root, entries),) = signatures.items()
    with pytest.raises(_bundle.BundleError, match="not in the bundle"):
        check({root: entries}, set())  # a root the pack does not carry
    with pytest.raises(_bundle.BundleError, match="tine-sig/3"):
        check({root: [{**entries[0], "block": {"scheme": "tine-sig/2"}}]}, {root})
    with pytest.raises(_bundle.BundleError):
        check({root: [{"block": entries[0]["block"]}]}, {root})


def test_descriptor_rewrite_waits_for_the_config_lock(room, monkeypatch):
    monkeypatch.setenv(FORMAT_ENV, "3")
    repo = Repo.init(room / "r")
    monkeypatch.delenv(FORMAT_ENV)
    held = threading.Event()

    def hold() -> None:
        with config_lock(repo.path):
            held.set()
            time.sleep(0.3)

    worker = threading.Thread(target=hold)
    worker.start()
    held.wait()
    started = time.monotonic()
    mark_v4(repo)
    assert time.monotonic() - started >= 0.2  # it waited instead of racing a gc
    worker.join()
    assert read_config(repo.path / "config.json")["objects"] == 4


# --------------------------------------------------------------------------- #
def _digests(paths: list[Path]) -> dict[str, str]:
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def _tree(root: Path) -> dict[str, str]:
    return _digests(sorted(p for p in root.rglob("*") if p.is_file()))


def test_reading_every_golden_fixture_leaves_its_bytes_untouched(room):
    artifacts = sorted((FIXTURES / "compat").glob("*/*.tine")) + sorted(
        FIXTURES.glob("golden_*.tine")
    )
    assert artifacts
    before = _digests(artifacts)
    for path in artifacts:
        Run.load(path)
        Run.verify_integrity(path)
        Run.verify_signature(path, hmac_key=b"compat-golden-signing-key-000001")
    assert _digests(artifacts) == before
    repos = sorted(p for p in (FIXTURES / "compat").glob("*/repo") if p.is_dir())
    assert len(repos) == 40
    for source in repos:
        copy = room / source.parent.name
        shutil.copytree(source, copy)
        tree = _tree(copy)  # derived indexes may appear; no fixture file may change
        repo = Repo.open(copy)
        assert repo.fsck().ok, source
        for name, oid in repo.list_refs().items():
            if name.startswith("heads/") and oid.startswith("run:"):
                repo.load_run(oid)
        after = _tree(copy)
        assert {name: after.get(name) for name in tree} == tree, source  # never re-marked v4


# --------------------------------------------------------------------------- #
# Recording never loses a run: a structural v4 misfit falls back to v2.
def _dangling(kind: str, run_id: str = "dangling", **extra) -> Run:
    run = _run(run_id, **extra)
    if kind == "pricing":
        run.manifest["pricing"] = {
            "invocations": [{"step_id": "gone-step", "status": "complete"}],
            "rate_cards": {"gone-step": "card"},
        }
    else:
        run.transcript.append({"role": "assistant", "content": "x", "step_id": "gone-step"})
    return run


def test_v4_object_bound_is_shared_and_far_above_long_runs():
    from opentine import _artifact_v4, _artifact_v4_read, _artifact_v4_repo

    bound = _format_v4.MAX_V4_OBJECTS
    assert bound >= 1_000_000
    for module in (_artifact_v4, _artifact_v4_read, _artifact_v4_repo):
        assert module.MAX_V4_OBJECTS is bound


def test_over_limit_object_count_saves_as_v2_with_a_warning(room, monkeypatch, capsys):
    from opentine import _artifact_v4

    monkeypatch.setattr(_artifact_v4, "MAX_V4_OBJECTS", 3)
    path = _run("long").save(room / "long.tine")
    data = read_artifact_json(path)
    assert data["format_version"] == 2 and Run.verify_integrity(path).ok
    err = capsys.readouterr().err
    assert "over the format v4 limit; saved as format 2" in err and "deprecated" not in err
    assert any("saved as format 2" in w for w in Run.load(path).metadata["warnings"])
    monkeypatch.setenv(FORMAT_ENV, "4")
    with pytest.raises(ValueError, match="format v4 limit"):
        _run("long").save(room / "strict.tine")
    assert not (room / "strict.tine").exists()


@pytest.mark.parametrize("kind", ["pricing", "transcript"])
def test_dangling_step_reference_saves_as_v2_by_default(room, monkeypatch, capsys, kind):
    path = _dangling(kind).save(room / f"{kind}.tine")
    assert read_artifact_json(path)["format_version"] == 2
    assert Run.verify_integrity(path).ok
    err = capsys.readouterr().err
    assert "unknown step; saved as format 2" in err
    loaded = Run.load(path)
    assert any("unknown step" in w for w in loaded.metadata["warnings"])
    monkeypatch.setenv(FORMAT_ENV, "4")
    with pytest.raises(ValueError, match="unknown step"):
        _dangling(kind).save(room / f"{kind}-strict.tine")
    assert not (room / f"{kind}-strict.tine").exists()


@pytest.mark.parametrize("kind", ["pricing", "transcript"])
def test_no_recorder_path_loses_a_run(room, capsys, kind):
    # explicit lenient save (harness wrapper, tine record) and the autosaver's
    # final and draft writes: wide integers and dangling references together.
    lenient = _dangling(kind, "lenient", n=WIDE)
    lenient.save(room / "lenient.tine", lenient=True)
    assert Run.load(room / "lenient.tine").steps[0].inputs["n"] == str(WIDE)
    final = _dangling(kind, "final", n=WIDE)
    Autosaver(room / "auto.tine").flush(final)
    assert Run.load(room / "auto.tine").id == "final"
    draft = _dangling(kind, "draft", n=WIDE)
    draft.status = RunStatus.running
    Autosaver(room / "draft.tine").flush(draft)
    assert Run.load(room / "draft.tine").id == "draft"
