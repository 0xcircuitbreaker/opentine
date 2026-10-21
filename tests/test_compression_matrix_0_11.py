"""0.11 storage compression across every surface, in every stored form.

The rest of the suite runs with ``OPENTINE_COMPRESS=0`` (it inspects stored
bytes directly), so this module repeats the core scenarios with compression on
-- zlib, zstd where the codec is available, and a repository packed by
``tine gc`` -- to make sure the compressed paths are exercised end to end.
"""

from __future__ import annotations

import json

import pytest

from opentine import Run, _codec
from opentine._actions_query import ActionQuery, find
from opentine._actions_source import open_repo, open_runs_dir
from opentine.cli import main
from opentine.graph import RunStatus, StepKind
from opentine.repository import Repo
from opentine.repository._gc import gc

MODES = ["zlib", *(["zstd"] if _codec.available("zstd") else []), "packed"]
KEY = b"k" * 32


@pytest.fixture(params=MODES)
def mode(request, monkeypatch):
    codec = "zlib" if request.param == "packed" else request.param
    monkeypatch.setenv("OPENTINE_COMPRESS", codec)
    return request.param


def _run(name: str = "matrix", steps: int = 15) -> Run:
    run = Run(id=name)
    for index in range(steps):
        run.add_step(
            StepKind.tool,
            {"name": "Bash", "arguments": {"command": f"cat /srv/app/{index}.log " * 10}},
            outputs={"result": "INFO request ok\n" * 60},
        )
    run.add_step(StepKind.done, {"text": "finished"})
    run.status = RunStatus.completed
    return run


def _repo(tmp_path, mode: str, name: str = "r") -> tuple[Repo, str]:
    repo = Repo.init(tmp_path / name)
    run_id = repo.put_run(_run(), ref="heads/main").run_id
    if mode == "packed":
        gc(repo, codec="zlib")
        repo = Repo.open(repo.path)
    return repo, run_id


def _stored_compressed(repo: Repo, mode: str) -> bool:
    if mode == "packed":
        return any((repo.path / "packs").glob("*.tpk"))
    files = [f for f in (repo.path / "objects").rglob("*") if f.is_file()]
    return any(f.read_bytes().startswith(_codec.MAGIC) for f in files)


def test_v2_round_trip_integrity_and_signature(tmp_path, mode):
    path = _run().save(tmp_path / "run.tine", sign_key=KEY)
    assert path.read_bytes().startswith(_codec.MAGIC)
    loaded = Run.load(path)
    assert len(loaded.steps) == 16
    assert Run.verify_integrity(path).ok
    assert Run.verify_signature(path, hmac_key=KEY).state == "verified"


def test_repository_round_trip_fsck_and_attestation(tmp_path, mode):
    repo, run_id = _repo(tmp_path, mode)
    assert _stored_compressed(repo, mode)
    assert len(repo.load_run(run_id).steps) == 16
    assert repo.fsck().ok
    oid = repo.attest(run_id, {"approved": True}, signer="ci", key=KEY)
    assert Repo.open(repo.path).verify_attestation(oid, hmac_key=KEY).state == "verified"


def test_transfer_in_both_directions(tmp_path, mode):
    source, run_id = _repo(tmp_path, mode, "source")
    plain = Repo.init(tmp_path / "plain", compression=None)
    plain.import_pack(source.pack())
    assert plain.fsck().ok and len(plain.load_run(run_id).steps) == 16
    again = Repo.init(tmp_path / "again")
    again.import_pack(plain.pack())
    if mode == "packed":
        gc(again, codec="zlib")
    assert Repo.open(again.path).fsck().ok
    assert sorted(Repo.open(again.path).iter_oids()) == sorted(source.iter_oids())


def test_export_and_reimport(tmp_path, mode):
    path = _run().save(tmp_path / "run.tine")
    out = tmp_path / "trace.json"
    main(["export", str(path), "--output", str(out)])
    document = json.loads(out.read_text(encoding="utf-8"))
    assert "resourceSpans" in document
    saved = tmp_path / "back.tine"
    main(["import", str(out), "--format", "otel-json", "--save", str(saved)])
    assert saved.read_bytes().startswith(_codec.MAGIC)
    assert Run.load(saved).steps


def test_actions_index_reads_compressed_runs_and_repositories(tmp_path, mode):
    runs = tmp_path / "runs"
    runs.mkdir()
    _run("a").save(runs / "a.tine")
    index, _ = open_runs_dir(runs)
    assert len(find(index, ActionQuery(tool="Bash"))) == 15
    repo, _ = _repo(tmp_path, mode)
    repo_index, _ = open_repo(repo)
    assert len(find(repo_index, ActionQuery(tool="Bash"))) == 15
