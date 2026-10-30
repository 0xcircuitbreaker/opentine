"""0.15.0 serverless sharing: bundles over a plain git remote (needs ``git``)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from opentine import Run, _bundle, _bundle_git
from opentine.graph import StepKind
from opentine.repository import Repo

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


@pytest.fixture(autouse=True)
def _isolated_git(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def _bare(tmp_path: Path) -> Path:
    path = tmp_path / "shared.git"
    subprocess.run(["git", "init", "-q", "--bare", str(path)], check=True)
    return path


def _origin(tmp_path: Path, label: str = "first") -> tuple[Repo, str]:
    repo = Repo.init(tmp_path / label)
    run = Run(id=label)
    run.add_step(StepKind.done, {"text": label})
    return repo, repo.put_run(run, ref="heads/main").run_id


def test_push_then_fetch_roundtrip_over_a_bare_repo(tmp_path: Path):
    remote = _bare(tmp_path)
    origin, oid = _origin(tmp_path)
    pushed = _bundle_git.push(origin, str(remote), None)
    assert pushed["ref"] == "refs/tine/bundle"
    target = Repo.init(tmp_path / "target")
    result = _bundle_git.fetch(target, str(remote), "shared")
    assert result["updated"] == {"remotes/shared/main": oid}
    again = _bundle_git.fetch(target, str(remote), "shared")
    assert again["updated"] == {}


def test_second_push_builds_on_the_first(tmp_path: Path):
    remote = _bare(tmp_path)
    origin, oid = _origin(tmp_path)
    first = _bundle_git.push(origin, str(remote), None)["commit"]
    event = origin.get(oid).payload()["events"][0]
    child = origin.fork(oid, event, ref="heads/main")
    second = _bundle_git.push(origin, str(remote), None)["commit"]
    parents = subprocess.run(
        ["git", "--git-dir", str(remote), "rev-parse", f"{second}^"],
        capture_output=True,
        check=True,
    )
    assert parents.stdout.decode().strip() == first
    target = Repo.init(tmp_path / "target")
    _bundle_git.fetch(target, str(remote), "shared")
    assert target.read_ref("remotes/shared/main") == child


def test_tampered_remote_blob_is_refused_before_refs_move(tmp_path: Path):
    remote = _bare(tmp_path)
    origin, _ = _origin(tmp_path)
    data = bytearray(_bundle.create(origin))
    data[-3] ^= 0x01
    blob = subprocess.run(
        ["git", "--git-dir", str(remote), "hash-object", "-w", "--stdin"],
        input=bytes(data),
        capture_output=True,
        check=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "--git-dir", str(remote), "mktree"],
        input=b"100644 blob " + blob + b"\tbundle.tine\n",
        capture_output=True,
        check=True,
    ).stdout.strip()
    commit = subprocess.run(
        ["git", "-c", "user.name=x", "-c", "user.email=x@x", "--git-dir", str(remote)]
        + ["commit-tree", tree.decode(), "-m", "evil"],
        capture_output=True,
        check=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "--git-dir", str(remote), "update-ref", "refs/tine/bundle", commit.decode()],
        check=True,
    )
    target = Repo.init(tmp_path / "target")
    with pytest.raises(_bundle.BundleError):
        _bundle_git.fetch(target, str(remote), "shared")
    assert target.list_refs() == {}


def test_missing_remote_ref_and_unsafe_remotes(tmp_path: Path):
    remote = _bare(tmp_path)
    with pytest.raises(KeyError):
        _bundle_git.fetch(Repo.init(tmp_path / "t"), str(remote), "shared")
    for bad in ("--upload-pack=touch /tmp/x", "ext::sh -c id", "http://example.com/x"):
        with pytest.raises(_bundle_git.GitTransportError):
            _bundle_git.remote_spec(bad)
