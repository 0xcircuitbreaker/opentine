"""0.61: memory provenance (served notes in step evidence) and quarantine."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _schemas, cli
from opentine._memory_index import consumers, rebuild
from opentine._memory_quarantine import lineage_findings, promote_refusals, quarantined
from opentine._memory_served import ServedError, record, record_with, served
from opentine.repository import Repo
from opentine.repository._holds import HoldError, release
from opentine.trace.recorder import Recorder
from opentine.trace.schema import TraceEvent

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _tine(capsys, *argv: str):
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    out = capsys.readouterr().out
    try:
        return code, json.loads(out)
    except ValueError:
        return code, out


@pytest.fixture
def team(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    Repo.init(tmp_path)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    path = tmp_path / "k.key"
    path.write_bytes(key.private_bytes_raw().hex().encode("ascii"))
    pub = key.public_key().public_bytes_raw().hex()
    assert _tine(capsys, "memory", "trust", pub, "--json")[0] == 0
    code, added = _tine(capsys, "memory", "add", "deploys", "Deploy with the blue pipeline",
                        "--key", path.as_posix(), "--json")  # fmt: skip
    assert code == 0, added
    return tmp_path, path.as_posix(), added["note"]["digest"]


def _run(repo: Repo, ref: str) -> Recorder:
    recorder = Recorder.start(repo, ref=ref, capture=False)
    recorder.append(TraceEvent("model", 1, "t", "s0", outputs={"text": "ok"}))
    return recorder


def _valid(document: dict) -> None:
    assert _schemas.validate_output(document) == [], document


def test_recall_records_the_served_note_in_the_running_run(team, capsys):
    root, _key, note = team
    repo = Repo.open(root)
    recorder = _run(repo, "heads/agent")
    code, found = _tine(capsys, "memory", "recall", "deploy", "--record-to", "heads/agent",
                        "--json")  # fmt: skip
    assert code == 0, found
    _valid(found)
    run = found["recorded_run"]
    assert run and served(repo, run) == [note]
    assert run != recorder.run_id  # a new run object: the served step is part of the run


def test_a_finished_or_attested_run_is_never_amended(team):
    root, _key, note = team
    repo = Repo.open(root)
    recorder = _run(repo, "heads/done")
    recorder.finalize()
    with pytest.raises(ServedError, match="finished"):
        record(repo, "heads/done", [{"digest": note}], "deploy")


def test_min_assurance_keeps_notes_whose_subject_run_reaches_the_tier(team, capsys):
    code, low = _tine(capsys, "memory", "recall", "deploy", "--min-assurance", "T0", "--json")
    assert [n["assurance"] for n in low["notes"]] == ["T0"]
    _valid(low)
    code, high = _tine(capsys, "memory", "recall", "deploy", "--min-assurance", "T1", "--json")
    assert code == 0 and high["notes"] == []


def _lineage(root, variant: str, run: str) -> None:
    folder = root / ".tine" / "lineage" / "variants"
    folder.mkdir(parents=True, exist_ok=True)
    claim = {"variant": variant, "mutation_run": run, "evals": []}
    (folder / f"{variant[7:]}.json").write_bytes(json.dumps({"claim": claim}).encode("utf-8"))


def test_quarantine_lists_runs_and_variants_and_blocks_promote_and_lineage(team, capsys):
    root, key, note = team
    repo = Repo.open(root)
    used = record_with(_run(repo, "heads/a"), [{"digest": note}], "deploy")
    assert used
    run = repo.read_ref("heads/a")
    clean = _run(repo, "heads/b").run_id
    variant = "sha256:" + "a" * 64
    _lineage(root, variant, run)
    _lineage(root, "sha256:" + "b" * 64, clean)
    code, out = _tine(capsys, "memory", "quarantine", note, "--key", key, "--why", "poisoned",
                      "--json")  # fmt: skip
    assert code == 0, out
    _valid(out)
    assert out["quarantined"] is True and run in {r["run"] for r in out["runs"]}
    assert clean not in {r["run"] for r in out["runs"]}
    assert [v["variant"] for v in out["variants"]] == [variant]
    code, recalled = _tine(capsys, "memory", "recall", "deploy", "--json")
    assert recalled["notes"] == []  # superseded: no longer served
    assert [r["code"] for r in promote_refusals(root, run)] == ["promote.memory-quarantined"]
    assert promote_refusals(root, clean) == []
    files = {p.relative_to(root / ".tine" / "lineage").as_posix(): p.read_bytes()
             for p in (root / ".tine" / "lineage").rglob("*.json")}  # fmt: skip
    found = lineage_findings(root, files, [variant, "sha256:" + "b" * 64])
    assert [(f["code"], f["variant"]) for f in found] == [("lineage.memory-quarantined", variant)]


def test_deleting_the_quarantine_ref_does_not_lift_it(team, capsys):
    root, key, note = team
    code, out = _tine(capsys, "memory", "quarantine", note, "--key", key, "--why", "bad",
                      "--json")  # fmt: skip
    repo = Repo.open(root)
    ref = next(r for r, oid in repo.list_refs().items() if oid == out["quarantine"])
    for path in (root / ".tine").rglob(ref.rsplit("/", 1)[-1]):
        path.unlink()  # a loop deletes the quarantine's ref
    assert ref not in repo.list_refs()
    assert note in quarantined(repo)
    code, recalled = _tine(capsys, "memory", "recall", "deploy", "--json")
    assert recalled["notes"] == []  # the held copy still keeps the note from being served
    with pytest.raises(HoldError, match="never released"):
        release(repo, out["held"])


def test_the_index_is_rebuildable_and_scales_by_counts(team):
    root, _key, note = team
    repo = Repo.open(root)
    runs = 40
    for number in range(runs):
        recorder = _run(repo, f"heads/r{number}")
        if number % 4 == 0:
            record_with(recorder, [{"digest": note}], "deploy")
    first = consumers(repo, note)
    assert len({r["run"] for r in first}) == runs // 4
    stats = rebuild(repo)
    assert stats["rows"] == len(first)
    assert consumers(repo, note) == first
    calls = []
    original = repo.get
    repo.get = lambda oid: calls.append(oid) or original(oid)  # type: ignore[method-assign]
    assert consumers(repo, note) == first
    assert calls == []  # a fresh index answers without reading a single object
