"""0.38: a captured turn links a workspace tree that ``tine rewind --tree`` uses."""

from __future__ import annotations

import json
from pathlib import Path

from opentine._hook_protocol import PROTOCOL, handle


def _repo(tmp_path, monkeypatch, config: dict) -> Path:
    from opentine import _porcelain_config as porcelain
    from opentine.repo import Repo

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    root = tmp_path / "repo"
    porcelain.save(Path(Repo.init(root).path), {"remotes": {}, "config": config})
    return root


def _turn(root: Path, cwd: Path) -> dict:
    payload = {"protocol": PROTOCOL, "event": "turn_end", "session": "s-1", "cwd": str(cwd)}
    return handle(json.dumps(payload).encode(), str(root), "generic")


def _last_outputs(root: Path, ref: str) -> dict:
    from opentine.repo import Repo

    repo = Repo.open(root)
    run = repo.load_run(repo.read_ref(ref))
    return run.steps[-1].outputs


def test_a_turn_links_a_tree_of_the_workspace(tmp_path, monkeypatch):
    from opentine._tree import read_tree
    from opentine.repo import Repo

    root = _repo(tmp_path, monkeypatch, {"hooks.capture": "true", "hooks.snapshot": "true"})
    work = tmp_path / "work"
    (work / "src").mkdir(parents=True)
    (work / "src" / "app.py").write_text("print('v1')\n")
    result = _turn(root, work)
    assert result["ok"]
    tree = _last_outputs(root, result["ref"])["tree"]
    entries = read_tree(Repo.open(root), tree)["entries"]
    assert any(entry["name"] == "src" for entry in entries)


def test_snapshots_stay_off_unless_configured(tmp_path, monkeypatch):
    root = _repo(tmp_path, monkeypatch, {"hooks.capture": "true"})
    work = tmp_path / "work"
    work.mkdir()
    (work / "a.txt").write_text("x")
    result = _turn(root, work)
    assert result["ok"] and "tree" not in _last_outputs(root, result["ref"])
