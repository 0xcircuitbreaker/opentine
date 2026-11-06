"""0.38: tree blobs, per-turn snapshots, exact-tree rewind, reachability, 0.34 compat."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import textwrap
from pathlib import Path

import pytest

from opentine.cli import main
from opentine.kernel import TREE_SCHEMA, KernelError, ObjectEnvelope, validate_links
from opentine.repository import Repo

posix = pytest.mark.skipif(sys.platform == "win32", reason="symlinks and modes are POSIX here")
ROOT = Path(__file__).resolve().parents[1]


def _snapshot(*args, **kwargs):
    from opentine._snapshot import snapshot

    return snapshot(*args, **kwargs)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    return Repo.init(tmp_path / "store")


@pytest.fixture
def ws(tmp_path):
    root = tmp_path / "ws"
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "main.py").write_bytes(b"print('hi')\n")
    (root / "src" / "pkg" / "util.py").write_bytes(b"X = 1\r\n\x00binary\xff")
    (root / "README.md").write_bytes(b"# readme\n")
    return root


def _files(root: Path) -> dict[str, bytes | str]:
    """Every tracked path: file bytes, or ``-> target`` for a link (VCS dirs left out)."""
    out: dict[str, bytes | str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", ".tine"}]
        for name in dirnames + filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if full.is_symlink():
                out[rel] = "-> " + os.readlink(full)
            elif full.is_file():
                out[rel] = full.read_bytes()
    return out


def test_a_tree_is_a_schema_2_blob_whose_entries_are_links(repo, ws):
    from opentine._tree import read_tree

    snap = _snapshot(repo, ws)
    envelope = repo.get(snap.oid)
    assert (envelope.object_type, envelope.schema) == ("blob", TREE_SCHEMA)
    tree = read_tree(repo, snap.oid)
    assert [entry["name"] for entry in tree["entries"]] == ["README.md", "src"]
    assert set(validate_links(envelope)) == {entry["oid"] for entry in tree["entries"]}
    assert repo.fsck().ok


def test_tree_blob_needs_its_children_and_blob_links():
    body = json.dumps(
        {"entries": [{"mode": "100644", "name": "a", "oid": "event:sha256:" + "0" * 64}]}
    ).encode()
    with pytest.raises(KernelError):
        validate_links(ObjectEnvelope.create("blob", body, TREE_SCHEMA))
    child = "blob:sha256:" + "1" * 64
    good = ObjectEnvelope.create(
        "blob",
        json.dumps({"entries": [{"mode": "100644", "name": "a", "oid": child}]}).encode(),
        TREE_SCHEMA,
    )
    assert validate_links(good) == (child,)
    with pytest.raises(KernelError, match="missing linked object"):
        validate_links(good, lambda oid: False)
    # A schema-1 blob that happens to look like a tree is plain content.
    assert validate_links(ObjectEnvelope.create("blob", good.body)) == ()


def test_an_event_links_its_tree(repo, ws):
    from opentine._tree import link_tree

    snap = _snapshot(repo, ws)
    event = repo.put("event", link_tree({"kind": "tool", "parent_ids": []}, snap.oid))
    assert snap.oid in validate_links(repo.get(event))
    with pytest.raises(KernelError):
        repo.put("event", {"kind": "tool", "parent_ids": [], "tree": event})


def test_ignores_control_dirs_and_size_limits(repo, ws):
    from opentine._tree import walk

    (ws / ".git").mkdir()
    (ws / ".git" / "HEAD").write_text("ref")
    (ws / ".gitignore").write_text("*.log\nbuild/\n!keep.log\n")
    (ws / "a.log").write_text("x")
    (ws / "keep.log").write_text("x")
    (ws / "build").mkdir()
    (ws / "build" / "out.o").write_text("x")
    (ws / "src" / ".gitignore").write_text("/local.txt\n")
    (ws / "src" / "local.txt").write_text("x")
    (ws / "big.bin").write_bytes(b"0" * 2048)
    (ws / "skip_me").mkdir()
    (ws / "skip_me" / "f").write_text("x")
    snap = _snapshot(repo, ws, ignore=["skip_me/"], max_file_bytes=1024)
    paths = {row[0]: row[1] for row in walk(repo, snap.oid)}
    assert "keep.log" in paths and "src/main.py" in paths
    for gone in (".git", ".git/HEAD", "a.log", "build", "src/local.txt", "skip_me"):
        assert gone not in paths
    assert paths["big.bin"] == "omitted"
    assert ("big.bin", "size") in snap.omitted


@posix
def test_symlinks_are_recorded_never_followed(repo, ws, tmp_path):
    from opentine._tree import walk

    outside = tmp_path / "secret"
    outside.mkdir()
    (outside / "key").write_text("do not capture")
    os.symlink(outside, ws / "escape")
    os.symlink("main.py", ws / "src" / "alias")
    snap = _snapshot(repo, ws)
    rows = {row[0]: row for row in walk(repo, snap.oid)}
    assert rows["escape"][1] == "120000" and "escape/key" not in rows
    assert repo.get(rows["escape"][2]).body == os.fsencode(str(outside))
    assert repo.get(rows["src/alias"][2]).body == b"main.py"


def _commit(repo, tree: str) -> str:
    from opentine._tree import link_tree

    event = repo.put("event", link_tree({"kind": "tool", "parent_ids": []}, tree))
    run = repo.put("run", {"events": [event], "roots": [event], "tips": [event]})
    repo.update_ref("heads/main", run)
    return run


def _du(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file() and not f.is_symlink())


def test_a_100_turn_session_costs_under_10_percent(repo, ws, tmp_path):
    """Snapshot bytes over 100 turns <= 10% of workspace size x turns (repo growth)."""
    for d in range(10):
        sub = ws / f"mod{d}"
        sub.mkdir()
        for f in range(20):
            (sub / f"file{f}.py").write_bytes(
                (
                    f"# module {d}/{f}\n" + "".join(f"def f{i}(): return {i}\n" for i in range(60))
                ).encode()
            )
    store = repo.path / "objects"
    before, total_ws, cache = _du(store), 0, None
    for turn in range(100):
        target = ws / f"mod{turn % 10}" / f"file{turn % 20}.py"
        target.write_bytes(target.read_bytes() + f"# turn {turn}\n".encode())
        if turn % 7 == 0:
            (ws / f"new{turn}.txt").write_bytes(f"turn {turn}\n".encode())
        total_ws += _du(ws)
        snap = _snapshot(repo, ws, cache=cache)
        cache = snap.cache
    growth = _du(store) - before
    ratio = growth / total_ws
    print(f"\n100-turn snapshot growth {growth} B / workspace x turns {total_ws} B = {ratio:.4f}")
    assert ratio <= 0.10
    assert repo.fsck().ok


def _rewind(capsys, *argv: str) -> dict:
    try:
        main(["rewind", *argv, "--json"])
    except SystemExit as exc:
        assert not exc.code, capsys.readouterr()
    return json.loads(capsys.readouterr().out)


def test_rewind_restores_shell_changes_byte_for_byte(repo, ws, capsys):
    (ws / "tool.sh").write_bytes(b"#!/bin/sh\necho hi\n")
    (ws / "tool.sh").chmod(0o755)
    if sys.platform != "win32":
        os.symlink("src/main.py", ws / "link")
    snap = _snapshot(repo, ws)
    expected = _files(ws)
    # A shell (not a tracked tool call) edits, deletes, adds and retypes paths.
    (ws / "src" / "main.py").write_bytes(b"rm -rf /\n")
    shutil.rmtree(ws / "src" / "pkg")
    (ws / "README.md").unlink()
    (ws / "extra").mkdir()
    (ws / "extra" / "new.txt").write_text("added")
    (ws / "tool.sh").chmod(0o644)
    if sys.platform != "win32":
        (ws / "link").unlink()
        (ws / "link").write_text("now a file")
    dry = _rewind(capsys, snap.oid, "--root", str(ws), "--repo", str(repo.path))
    assert not dry["applied"] and (ws / "extra" / "new.txt").exists()
    done = _rewind(capsys, snap.oid, "--root", str(ws), "--repo", str(repo.path), "--apply")
    assert done["applied"]
    assert _files(ws) == expected
    assert not (ws / "extra").exists()
    if sys.platform != "win32":
        assert os.stat(ws / "tool.sh").st_mode & 0o777 == 0o755
    again = _rewind(capsys, snap.oid, "--root", str(ws), "--repo", str(repo.path))
    assert again["restore"] == [] and again["remove"] == []


def test_rewind_leaves_ignored_and_omitted_paths_alone(repo, ws, capsys):
    (ws / ".gitignore").write_text("*.log\n")
    (ws / "big.bin").write_bytes(b"1" * 4096)
    snap = _snapshot(repo, ws, max_file_bytes=1024)
    (ws / "run.log").write_text("keep me")
    (ws / "big.bin").write_bytes(b"2" * 4096)
    (ws / ".git").mkdir()
    (ws / ".git" / "config").write_text("[core]")
    _rewind(capsys, snap.oid, "--root", str(ws), "--repo", str(repo.path), "--apply")
    assert (ws / "run.log").read_text() == "keep me"
    assert (ws / "big.bin").read_bytes() == b"2" * 4096
    assert (ws / ".git" / "config").read_text() == "[core]"


def test_rewind_refuses_control_dirs_unless_allowed(repo, ws, capsys):
    (ws / ".github" / "workflows").mkdir(parents=True)
    (ws / ".github" / "workflows" / "ci.yml").write_text("safe")
    snap = _snapshot(repo, ws)
    (ws / ".github" / "workflows" / "ci.yml").write_text("evil")
    payload = _rewind(capsys, snap.oid, "--root", str(ws), "--repo", str(repo.path), "--apply")
    assert [row["path"] for row in payload["refused"]] == [".github/workflows/ci.yml"]
    assert (ws / ".github" / "workflows" / "ci.yml").read_text() == "evil"
    _rewind(
        capsys,
        *(snap.oid, "--root", str(ws), "--repo", str(repo.path), "--apply"),
        "--allow-control-dirs",
    )
    assert (ws / ".github" / "workflows" / "ci.yml").read_text() == "safe"


@posix
def test_rewind_writes_through_no_swapped_link(repo, ws, tmp_path):
    from opentine._rewind import RewindError
    from opentine._rewind_tree import apply_tree, plan_tree

    snap = _snapshot(repo, ws)
    (ws / "src" / "main.py").write_text("changed")
    plan = plan_tree(repo, snap.oid, ws)
    outside = tmp_path / "outside"
    outside.mkdir()
    shutil.rmtree(ws / "src")
    os.symlink(outside, ws / "src")  # swapped in after the plan was made
    with pytest.raises(RewindError):
        apply_tree(repo, plan, ws)
    assert list(outside.iterdir()) == []


def test_rewind_from_a_run_step_uses_its_linked_tree(repo, ws, tmp_path, capsys):
    from opentine import Run
    from opentine.core import StepKind

    snap = _snapshot(repo, ws)
    run = Run(user_prompt="edit")
    run.add_step(StepKind.tool, inputs={"name": "Bash"}, outputs={"tree": snap.oid})
    run.add_step(StepKind.tool, inputs={"name": "Bash"}, outputs={})
    saved = tmp_path / "r.tine"
    run.save(saved)
    (ws / "README.md").write_text("shell edit")
    payload = _rewind(
        capsys, f"{saved}@1", "--tree", "--root", str(ws), "--repo", str(repo.path), "--apply"
    )
    assert payload["tree"] == snap.oid and payload["step_index"] == 1
    assert (ws / "README.md").read_bytes() == b"# readme\n"


def test_reachability_walks_trees(repo, ws):
    from opentine._bundle import create, unbundle, verify
    from opentine._tree import walk
    from opentine.repository._gc_prune import plan
    from opentine.repository.pack import install_pack, reachable

    snap = _snapshot(repo, ws)
    event = _commit(repo, snap.oid)
    leaves = {row[2] for row in walk(repo, snap.oid)}
    assert leaves <= set(reachable(repo, [event]))
    assert not plan(repo, min_age=0).candidates  # every tree child is kept
    other = Repo.init(repo.path.parent / "other")
    install_pack(other, repo.pack(reachable(repo, [event])))
    assert other.fsck().ok and leaves <= set(other.iter_oids())
    third = Repo.init(repo.path.parent / "third")
    unbundle(third, create(repo, ["main"]), "peer")
    assert third.fsck().ok and leaves <= set(third.iter_oids())
    assert verify(create(repo, ["main"]))


OLD_READER = textwrap.dedent(
    """
    import sys
    sys.path.insert(0, sys.argv[1])
    import opentine
    assert opentine.__file__.startswith(sys.argv[1]), opentine.__file__
    from opentine.repository.store import Repo
    from opentine.repository.pack import install_pack
    repo = Repo.open(sys.argv[2])
    result = repo.fsck()
    assert result.ok, result.errors
    fresh = Repo.init(sys.argv[4])
    install_pack(fresh, open(sys.argv[3], "rb").read())
    assert fresh.fsck().ok
    assert set(repo.iter_oids()) <= set(fresh.iter_oids())
    fresh.pack()
    print("ok", opentine.__version__)
    """
)


def _v034(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    try:
        archive = subprocess.run(
            ["git", "-C", str(ROOT), "archive", "v0.34.0", "opentine"],
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("tag v0.34.0 is not available in this checkout")
    dest = tmp_path / "v034"
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(dest, filter="data")
    return dest


def test_the_034_fsck_and_pack_reader_accept_a_repo_with_trees(repo, ws, tmp_path):
    old = _v034(tmp_path)
    _commit(repo, _snapshot(repo, ws).oid)
    pack = tmp_path / "trees.pack"
    pack.write_bytes(repo.pack())
    script = tmp_path / "old_reader.py"
    script.write_text(OLD_READER)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    done = subprocess.run(
        [sys.executable, str(script), str(old), str(repo.path), str(pack), str(tmp_path / "o")],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("ok 0.34.0")
