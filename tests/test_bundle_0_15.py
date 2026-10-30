"""0.15.0 serverless sharing: single-file bundles (no git binary needed)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from opentine import Run, _bundle
from opentine._cli_bundle import add_bundle_parsers, cmd_bundle
from opentine.graph import StepKind
from opentine.kernel import canonical_json
from opentine.repository import Repo


def _run(label: str) -> Run:
    run = Run(id=label)
    run.add_step(StepKind.done, {"text": label})
    return run


def _origin(tmp_path: Path) -> tuple[Repo, str]:
    repo = Repo.init(tmp_path / "origin")
    oid = repo.put_run(_run("first"), ref="heads/main").run_id
    return repo, oid


def _forge(refs: dict, pack: bytes) -> bytes:
    manifest = canonical_json(
        {
            "format": _bundle.FORMAT,
            "pack": "sha256:" + hashlib.sha256(pack).hexdigest(),
            "pack_bytes": len(pack),
            "refs": refs,
        }
    )
    body = len(manifest).to_bytes(4, "big") + manifest + pack
    return _bundle.MAGIC + hashlib.sha256(body).digest() + body


def test_roundtrip_create_verify_import(tmp_path: Path):
    origin, oid = _origin(tmp_path)
    data = _bundle.create(origin)
    checked = _bundle.verify(data)
    assert checked.refs == {"heads/main": oid}
    target = Repo.init(tmp_path / "target")
    result = _bundle.unbundle(target, data, "friend")
    assert result["updated"] == {"remotes/friend/main": oid}
    assert target.read_ref("remotes/friend/main") == oid
    assert target.load_run(oid) is not None


def test_reimport_is_idempotent(tmp_path: Path):
    origin, oid = _origin(tmp_path)
    data = _bundle.create(origin, ["main"])
    target = Repo.init(tmp_path / "target")
    _bundle.unbundle(target, data, "friend")
    again = _bundle.unbundle(target, data, "friend")
    assert again["updated"] == {} and again["unchanged"] == ["remotes/friend/main"]


def test_fast_forward_accepted_divergence_refused_without_force(tmp_path: Path):
    origin, oid = _origin(tmp_path)
    target = Repo.init(tmp_path / "target")
    _bundle.unbundle(target, _bundle.create(origin), "friend")
    event = origin.get(oid).payload()["events"][0]
    child = origin.fork(oid, event, ref="heads/main")
    _bundle.unbundle(target, _bundle.create(origin), "friend")  # descendant: ok
    assert target.read_ref("remotes/friend/main") == child
    other = Repo.init(tmp_path / "other")
    unrelated = other.put_run(_run("unrelated"), ref="heads/main").run_id
    diverged = _bundle.create(other)
    with pytest.raises(_bundle.BundleError, match="fast-forward"):
        _bundle.unbundle(target, diverged, "friend")
    assert target.read_ref("remotes/friend/main") == child
    _bundle.unbundle(target, diverged, "friend", force=True)
    assert target.read_ref("remotes/friend/main") == unrelated


@pytest.mark.parametrize("cut", [1, 40, 200])
def test_truncated_bundle_fails(tmp_path: Path, cut: int):
    data = _bundle.create(_origin(tmp_path)[0])
    with pytest.raises(_bundle.BundleError):
        _bundle.verify(data[:-cut])


def test_any_flipped_byte_fails(tmp_path: Path):
    data = bytearray(_bundle.create(_origin(tmp_path)[0]))
    for index in (0, len(_bundle.MAGIC) + 3, len(_bundle.MAGIC) + 40, len(data) - 5):
        tampered = bytearray(data)
        tampered[index] ^= 0x01
        with pytest.raises(_bundle.BundleError):
            _bundle.verify(bytes(tampered))
    target = Repo.init(tmp_path / "target")
    data[-5] ^= 0x01
    with pytest.raises(_bundle.BundleError):
        _bundle.unbundle(target, bytes(data), "friend")
    assert target.list_refs() == {}


def test_oversized_file_and_bytes_refused(tmp_path: Path, monkeypatch):
    path = tmp_path / "big.tine"
    path.write_bytes(b"x" * 64)
    with pytest.raises(_bundle.BundleError, match="maximum size"):
        _bundle.read_file(path, limit=32)
    monkeypatch.setattr(_bundle, "MAX_BUNDLE_BYTES", 16)
    with pytest.raises(_bundle.BundleError, match="maximum size"):
        _bundle.verify(b"x" * 17)


@pytest.mark.parametrize(
    "name",
    ["heads/../../etc", "/heads/main", "heads/ma\x00in", "heads/a\nb", "remotes/x/main", "HEADS/x"],
)
def test_malicious_ref_names_refused(tmp_path: Path, name: str):
    origin, oid = _origin(tmp_path)
    pack = _bundle.verify(_bundle.create(origin)).pack
    forged = _forge({name: oid}, pack)
    target = Repo.init(tmp_path / "target")
    with pytest.raises(_bundle.BundleError):
        _bundle.unbundle(target, forged, "friend")
    assert target.list_refs() == {}


def test_ref_pointing_outside_the_pack_refused(tmp_path: Path):
    origin, _ = _origin(tmp_path)
    pack = _bundle.verify(_bundle.create(origin)).pack
    with pytest.raises(_bundle.BundleError, match="outside"):
        _bundle.verify(_forge({"heads/main": "run:sha256:" + "0" * 64}, pack))


@pytest.mark.parametrize("bad", ["../x", "a/b", "", "Upper", "x" * 80])
def test_bad_namespace_refused(tmp_path: Path, bad: str):
    origin, _ = _origin(tmp_path)
    with pytest.raises(_bundle.BundleError):
        _bundle.unbundle(Repo.init(tmp_path / "t"), _bundle.create(origin), bad)


def test_cli_create_verify_unbundle(tmp_path: Path, capsys):
    import argparse

    origin, oid = _origin(tmp_path)
    parser = argparse.ArgumentParser()
    add_bundle_parsers(parser.add_subparsers(dest="command"))
    path = tmp_path / "Team Runs.tine"
    target = tmp_path / "target"
    Repo.init(target)
    for argv in (
        ["bundle", "create", str(path), "--all", "--repo", str(tmp_path / "origin")],
        ["bundle", "verify", str(path)],
        ["bundle", "unbundle", str(path), "--repo", str(target)],
    ):
        cmd_bundle(parser.parse_args(argv), None)
    assert '"verified": true' in capsys.readouterr().out
    assert Repo.open(target).read_ref("remotes/team-runs/main") == oid
