"""Format v4 in v3 repositories (0.26, SPEC 2.2 and 9.10).

The descriptor says object format 4 before the first v4 object; ``min_reader``
is enforced; a 0.13-0.25 reader refuses a v4 descriptor; a repository run and
its v4 file share one oid; v3 and v4 runs coexist under fsck; importing a v4
file keeps its oids and signatures; bundles carry v4 objects; and a golden v3
repository is read without being touched when ``OPENTINE_FORMAT`` is unset.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, _bundle, cli
from opentine._artifact_io import read_artifact_bytes, read_artifact_json
from opentine._artifact_v4 import read_v4, write_v4
from opentine._artifact_v4_repo import export_v4
from opentine._provenance_v4 import build
from opentine.kernel import canonical_json
from opentine.repo import Repo
from opentine.repository import _storage
from opentine.repository._config import V4_MIN_READER, read_config
from opentine.repository._sig_sidecar import sidecar_path

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN_REPO = FIXTURES / "compat" / "v0_18_0" / "repo"


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1767225600")
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _run(run_id: str = "repo-v4", **extra) -> Run:
    run = Run(id=run_id, model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.think, {"text": "thinking", **extra}, {"a": [1, 0.5]})
    run.add_step(StepKind.done, {"text": "done"}, cost=0.25)
    run.status = RunStatus.completed
    return run


def _config(repo: Repo) -> dict:
    return json.loads((repo.path / "config.json").read_bytes())


def _tine(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, " ".join((captured.out + captured.err).split())


def _reader_0_25(config: bytes) -> None:
    """The descriptor check every 0.13-0.25 reader runs (SPEC 2.2 before 0.26)."""
    value = json.loads(config)
    fixed = {"format": 3, "object_hash": "sha256", "repository": "opentine"}
    if any(value.get(key) != expected for key, expected in fixed.items()):
        raise ValueError("repository config is incompatible")
    if value.get("version") not in (1, 2, 3):
        raise ValueError("repository config is incompatible")


def test_descriptor_is_written_before_the_first_v4_object(room, monkeypatch):
    monkeypatch.setenv("OPENTINE_FORMAT", "3")  # an object-format-3 repository (pre-0.26)
    repo = Repo.init(room / "r")
    assert "objects" not in _config(repo)
    seen: list[dict] = []
    original = _storage.write_object

    def spy(target, oid, raw):
        seen.append(_config(target))
        return original(target, oid, raw)

    monkeypatch.setattr(_storage, "write_object", spy)
    monkeypatch.setenv("OPENTINE_FORMAT", "4")
    repo.put_run(_run())
    assert seen and all(c["objects"] == 4 and c["min_reader"] == V4_MIN_READER for c in seen)
    config = _config(repo)
    assert "format" not in config and config["version"] == _config(repo)["version"]
    assert config["version"] in (1, 2)  # storage version: untouched by object format 4


def test_storage_upgrade_keeps_object_format(room, monkeypatch):
    from opentine.repository._gc import set_storage_version

    monkeypatch.setenv("OPENTINE_FORMAT", "4")
    repo = Repo.init(room / "r", compression="zlib")
    repo.put_run(_run())
    set_storage_version(repo, 3, "zlib")
    set_storage_version(repo, 2, "zlib")
    assert _config(repo)["objects"] == 4 and Repo.open(room / "r").fsck().ok


def test_min_reader_newer_than_this_build_is_refused(room):
    repo = Repo.init(room / "r")
    config = {**_config(repo), "min_reader": "0.99.0"}
    (repo.path / "config.json").write_bytes(canonical_json(config))
    with pytest.raises(ValueError, match=r"needs opentine 0\.99\.0 or newer"):
        Repo.open(room / "r")
    config["min_reader"] = "next"
    (repo.path / "config.json").write_bytes(canonical_json(config))
    with pytest.raises(ValueError, match="min_reader"):
        Repo.open(room / "r")


@pytest.mark.parametrize(
    "change",
    [{"format": 3}, {"min_reader": None}, {"objects": True}, {"objects": 5}],
    ids=["format-and-objects", "no-min-reader", "bool-objects", "objects-5"],
)
def test_malformed_v4_descriptor_is_refused(room, monkeypatch, change):
    monkeypatch.setenv("OPENTINE_FORMAT", "4")
    repo = Repo.init(room / "r")
    repo.put_run(_run())
    config = {k: v for k, v in {**_config(repo), **change}.items() if v is not None}
    (repo.path / "config.json").write_bytes(canonical_json(config))
    with pytest.raises(ValueError, match="incompatible"):
        read_config(repo.path / "config.json")


def test_an_old_reader_refuses_a_v4_repository(room, monkeypatch):
    monkeypatch.setenv("OPENTINE_FORMAT", "3")  # an object-format-3 repository (pre-0.26)
    repo = Repo.init(room / "r")
    _reader_0_25((repo.path / "config.json").read_bytes())  # a v3 descriptor: accepted
    monkeypatch.setenv("OPENTINE_FORMAT", "4")
    repo.put_run(_run())
    with pytest.raises(ValueError, match="incompatible"):
        _reader_0_25((repo.path / "config.json").read_bytes())
    assert Repo.open(room / "r").fsck().ok  # while this build reads it


def test_repository_oid_equals_the_v4_file_root(room, monkeypatch):
    monkeypatch.setenv("OPENTINE_FORMAT", "4")
    run = _run(cost_hint=0.1)
    run.add_tag("t")
    repo = Repo.init(room / "r")
    oid = repo.put_run(run).run_id
    assert read_artifact_json_bytes(write_v4(run))["root"] == oid
    assert read_v4(export_v4(repo, oid))._v4_origin["root"] == oid
    loaded = repo.load_run(oid)
    loaded._v4_upgraded_from = build(
        "tine-repo/3",
        oid,
        integrity_digest=None,
        scheme=None,
        state="not-applicable",
        key_fingerprint=None,
        trust_basis="test",
    )
    upgraded = repo.put_run(loaded).run_id  # upgraded_from is carried into the payload
    assert repo.get(upgraded).payload()["upgraded_from"]["digest"] == oid
    assert read_artifact_json_bytes(write_v4(repo.load_run(upgraded)))["root"] == upgraded


def read_artifact_json_bytes(encoded: bytes) -> dict:
    return json.loads(encoded)


def test_v4_mode_refuses_what_v3_mode_stringifies(room, monkeypatch):
    monkeypatch.setenv("OPENTINE_FORMAT", "3")  # the deprecated legacy repository writer
    repo = Repo.init(room / "r")
    assert repo.put_run(_run("wide", n=2**60)).run_id  # v3: json_safe stringifies
    monkeypatch.setenv("OPENTINE_FORMAT", "4")
    other = Repo.init(room / "r4")
    with pytest.raises(ValueError, match="beyond 2\\*\\*53-1"):
        other.put_run(_run("wide", n=2**60))
    # A new repository is object format 4 from Repo.init (0.26); nothing was written.
    assert _config(other)["objects"] == 4 and not other.iter_oids()


def test_mixed_repository_passes_fsck(room, monkeypatch):
    monkeypatch.setenv("OPENTINE_FORMAT", "3")  # v3 objects first, as 0.25 wrote them
    repo = Repo.init(room / "r")
    v3 = repo.put_run(_run("a"), ref="heads/a").run_id
    monkeypatch.setenv("OPENTINE_FORMAT", "4")
    run = _run("b")
    run._v4_upgraded_from = build(
        "tine/2",
        "0" * 64,
        integrity_digest=None,
        scheme=None,
        state="unsigned",
        key_fingerprint=None,
        trust_basis="test",
    )
    v4 = repo.put_run(run, ref="heads/b").run_id
    result = Repo.open(room / "r").fsck()
    assert result.ok, result.errors
    assert {v3, v4} <= set(repo.iter_oids())
    bad = dict(repo.get(v4).payload(), upgraded_from={"format": "nope"})
    broken = repo.put("run", bad)
    errors = Repo.open(room / "r").fsck().errors
    assert any(broken in e and "upgraded_from" in e for e in errors)


def test_import_of_a_v4_file_keeps_oids_and_signatures(room, monkeypatch, capsys):
    monkeypatch.setenv("OPENTINE_FORMAT", "4")
    run = _run()
    run.add_tag("keep")
    run.metadata["note"] = "kept"
    run.save(room / "s.tine", sign_key=b"k" * 32)
    original = read_artifact_json(room / "s.tine")
    assert original["signatures"] and original["annotations"]
    monkeypatch.delenv("OPENTINE_FORMAT")
    Repo.init(room / "repo")
    code, out = _tine(capsys, "import", "s.tine", "--repo", "repo")
    assert code == 0, out
    repo = Repo.open(room / "repo")
    assert repo.read_ref("heads/main") == original["root"]
    assert set(original["objects"]) <= set(repo.iter_oids())
    assert sidecar_path(repo, original["root"]).is_file()
    loaded = repo.load_run(original["root"])
    assert "keep" in loaded.tags and loaded.metadata["note"] == "kept"
    assert repo.fsck().ok
    argv = ("migrate", "heads/main", "--to", "v4", "--repo", "repo", "-o", "back.tine")
    code, out = _tine(capsys, *argv)
    assert code == 0, out
    assert read_artifact_bytes(room / "back.tine") == read_artifact_bytes(room / "s.tine")
    code, out = _tine(capsys, "import", "s.tine", "--repo", "repo")  # idempotent
    assert code == 0 and "0 new of" in out and "0 new signature" in out
    code, out = _tine(capsys, "import", "s.tine", "--repo", "repo", "--save", "x.tine")
    assert code == 1 and "--save" in out


def test_bundle_round_trip_carries_v4_objects(room, monkeypatch):
    monkeypatch.setenv("OPENTINE_FORMAT", "4")
    source = Repo.init(room / "a")
    oid = source.put_run(_run(), ref="heads/main").run_id
    data = _bundle.create(source, ["heads/main"])
    target = Repo.init(room / "b")
    _bundle.unbundle(target, data, "a")
    assert target.read_ref("remotes/a/main") == oid
    assert export_v4(target, oid) == export_v4(source, oid)
    assert target.fsck().ok


def _tree(root: Path) -> dict[str, str]:
    files = sorted(p for p in root.rglob("*") if p.is_file())
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def test_golden_v3_repository_is_read_untouched(room):
    shutil.copytree(GOLDEN_REPO, room / "repo")
    before = _tree(room / "repo")
    repo = Repo.open(room / "repo")
    assert repo.fsck().ok
    assert repo.load_run("heads/main").steps
    assert _tree(room / "repo") == before
