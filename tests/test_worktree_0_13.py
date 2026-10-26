"""0.13 F3: ``tine worktree add/list/remove/prune`` -- isolated per-branch directories."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from opentine import Run, StepKind, _worktree, cli
from opentine.repository import Repo
from opentine.repository._prune_roots import file_roots


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    store = Repo.init(tmp_path / "project")
    run = Run(id="base0001", model_info="m")
    run.add_step(StepKind.model, {"text": "q"}, {"text": "a"})
    store.put_run(run, ref="heads/main")
    return store


def _cli(capsys, argv):
    capsys.readouterr()
    cli.main([*argv, "--repo", "project", "--json"])
    return json.loads(capsys.readouterr().out)


def test_add_list_remove_round_trip(repo, capsys, tmp_path):
    added = _cli(capsys, ["worktree", "add", str(tmp_path / "wt1"), "heads/main"])["result"]
    assert added["name"] == "wt1" and added["run"] == repo.read_ref("heads/main")
    marker = json.loads((tmp_path / "wt1" / ".tine-worktree").read_text())
    assert marker["repo"] == str(repo.path.resolve())
    rows = _cli(capsys, ["worktree", "list"])["result"]
    assert [(r["name"], r["state"]) for r in rows] == [("wt1", "ok")]
    _cli(capsys, ["worktree", "remove", "wt1"])
    assert not (tmp_path / "wt1").exists() and _cli(capsys, ["worktree", "list"])["result"] == []


def test_the_registration_is_a_prune_root(repo, tmp_path):
    entry = _worktree.add(repo, tmp_path / "wt", "heads/main")
    assert entry["run"] in file_roots(repo.path)


def test_a_worktree_with_files_needs_force(repo, tmp_path):
    _worktree.add(repo, tmp_path / "wt", "heads/main")
    (tmp_path / "wt" / "work.txt").write_text("x")
    with pytest.raises(ValueError, match="--force"):
        _worktree.remove(repo, "wt")
    _worktree.remove(repo, "wt", force=True)
    assert not (tmp_path / "wt").exists()


@pytest.mark.parametrize("name", ["../evil", "a/b", "UPPER", "", ".hidden", "x" * 80])
def test_names_are_one_safe_component(repo, tmp_path, name):
    with pytest.raises(ValueError):
        _worktree.add(repo, tmp_path / "wt", "heads/main", name=name)


def test_targets_inside_the_repository_or_non_empty_are_refused(repo, tmp_path):
    for target in (repo.path / "inside", repo.path, tmp_path):  # tmp_path holds the repo
        with pytest.raises(ValueError):
            _worktree.add(repo, target, "heads/main", name="x")
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "f").write_text("x")
    with pytest.raises(ValueError, match="empty"):
        _worktree.add(repo, busy, "heads/main")


def test_a_symlinked_target_is_refused(repo, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    with pytest.raises(ValueError, match="symlink"):
        _worktree.add(repo, link, "heads/main")


def test_a_tampered_registry_cannot_delete_another_directory(repo, tmp_path):
    _worktree.add(repo, tmp_path / "wt", "heads/main")
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "precious").write_text("keep me")
    entry_path = repo.path / "worktrees" / "wt.json"
    entry = json.loads(entry_path.read_text())
    entry["path"] = str(victim)
    entry_path.write_text(json.dumps(entry))
    with pytest.raises(ValueError, match="refusing"):
        _worktree.remove(repo, "wt", force=True)
    assert (victim / "precious").read_text() == "keep me"
    assert _worktree.prune(repo) == ["wt"]  # drops the registration only
    assert (victim / "precious").exists()


def test_prune_forgets_missing_directories(repo, tmp_path):
    _worktree.add(repo, tmp_path / "a", "heads/main")
    _worktree.add(repo, tmp_path / "b", "heads/main")
    (tmp_path / "a" / ".tine-worktree").unlink()
    (tmp_path / "a").rmdir()
    assert _worktree.prune(repo) == ["a"]
    assert [row["name"] for row in _worktree.list_worktrees(repo)] == ["b"]


def test_a_malformed_registry_entry_is_listed_invalid_not_trusted(repo):
    directory = repo.path / "worktrees"
    directory.mkdir(exist_ok=True)
    (directory / "bad.json").write_text('{"format": "x"}')
    (row,) = _worktree.list_worktrees(repo)
    assert row["state"] == "invalid"
    with pytest.raises(ValueError):
        _worktree.remove(repo, "bad")


def test_git_commit_argument_cannot_be_an_option(repo, tmp_path):
    with pytest.raises(ValueError, match="--git"):
        _worktree.add(repo, tmp_path / "wt", "heads/main", git="--upload-pack=evil")
    assert not (tmp_path / "wt").exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_git_paired_worktree(repo, tmp_path):
    project = repo.path.parent
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    (project / "README").write_text("x")
    for argv in (["init", "-q"], ["add", "README"], ["commit", "-q", "-m", "init"]):
        subprocess.run(["git", *argv], cwd=project, env=env, check=True, capture_output=True)
    entry = _worktree.add(repo, tmp_path / "gwt", "heads/main", git="HEAD")
    assert (Path(entry["path"]) / "README").exists()
    _worktree.remove(repo, "gwt", force=True)
    assert not (tmp_path / "gwt").exists()
