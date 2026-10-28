"""0.13 F3: ``Repo.update_refs`` -- atomic multi-ref updates with a crash journal."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from opentine import Run, StepKind, cli
from opentine.kernel import canonical_json
from opentine.repository import Repo
from opentine.repository import _ref_txn as txn
from opentine.repository._lockfile import stamp
from opentine.repository._reflog import read_reflog

ROOT = Path(__file__).resolve().parents[1]


def _run(store: Repo, label: str, ref: str | None = None) -> str:
    run = Run(id=f"r{label}", model_info="m")
    run.add_step(StepKind.model, {"text": label}, {"text": "ok"})
    return store.put_run(run, ref=ref).run_id


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    return Repo.init(tmp_path)


def test_update_refs_moves_every_ref_and_writes_reflogs(repo):
    a, b = _run(repo, "a"), _run(repo, "b")
    repo.update_refs([("heads/x", a, None), ("experiments/y", b, None)], actor="unit")
    assert repo.read_ref("heads/x") == a and repo.read_ref("experiments/y") == b
    assert read_reflog(repo.path, "heads/x")[0]["actor"] == "unit"
    assert not list((repo.path / "txn").glob("*"))  # journal and locks are gone


def test_one_failed_compare_and_swap_moves_nothing(repo):
    a, b = _run(repo, "a"), _run(repo, "b")
    repo.update_refs([("heads/x", a, None)])
    with pytest.raises(ValueError, match="concurrent ref update"):
        repo.update_refs([("heads/new", b, None), ("heads/x", b, None)])  # x is a, not None
    assert repo.read_ref("heads/new") is None and repo.read_ref("heads/x") == a
    assert not list((repo.path / "txn").glob("*"))


@pytest.mark.parametrize("rows", [[], "dup"])
def test_empty_or_duplicate_updates_are_refused(repo, rows):
    a = _run(repo, "a")
    if rows == "dup":
        rows = [("heads/x", a, None), ("refs/heads/x", a, None)]
    with pytest.raises(ValueError):
        repo.update_refs(rows)


def test_typed_namespaces_are_checked_before_anything_is_locked(repo):
    a = _run(repo, "a")
    blob = repo.put("blob", b"x")
    with pytest.raises(ValueError):
        repo.update_refs([("heads/x", a, None), ("heads/y", blob, None)])
    assert repo.read_ref("heads/x") is None


def _journal(repo: Repo, rows: list[dict], *, txn_id: str = "a" * 32, actor="t") -> Path:
    directory = repo.path / "txn"
    directory.mkdir(exist_ok=True)
    record = {"actor": actor, "format": txn.TXN_FORMAT, "id": txn_id, "updates": rows}
    path = directory / f"{txn_id}.json"
    path.write_bytes(canonical_json(record))
    return path


def _dead_lock(path: Path) -> None:
    """A lock stamped on this host by a pid that cannot exist: provably dead."""
    raw = stamp().decode().split()
    path.write_text(f"999999999 {raw[1]} {raw[2]}\n")


def test_an_abandoned_journal_is_rolled_forward_by_the_next_write(repo):
    a, b, c = _run(repo, "a"), _run(repo, "b"), _run(repo, "c")
    repo.update_refs([("heads/x", a, None)])
    path = _journal(
        repo,
        [{"new": b, "old": a, "ref": "heads/x"}, {"new": b, "old": None, "ref": "heads/y"}],
    )
    _dead_lock(path.with_suffix(".lock"))
    repo.update_ref("heads/other", c)  # any write recovers first
    assert repo.read_ref("heads/x") == b and repo.read_ref("heads/y") == b
    assert read_reflog(repo.path, "heads/y")[0]["actor"] == "txn-recover:t"
    assert not path.exists()


def test_roll_forward_never_clobbers_a_ref_moved_since(repo):
    a, b, c = _run(repo, "a"), _run(repo, "b"), _run(repo, "c")
    repo.update_refs([("heads/x", c, None)])
    path = _journal(repo, [{"new": b, "old": a, "ref": "heads/x"}])
    _dead_lock(path.with_suffix(".lock"))
    assert repo.recover_refs() == ["a" * 32]
    assert repo.read_ref("heads/x") == c


def test_a_live_transaction_is_left_to_its_owner(repo):
    a = _run(repo, "a")
    path = _journal(repo, [{"new": a, "old": None, "ref": "heads/x"}])
    path.with_suffix(".lock").write_bytes(stamp())  # this (live) process
    assert repo.recover_refs() == []
    assert path.exists() and repo.read_ref("heads/x") is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda rows, oid: [{"new": oid, "old": None, "ref": "../../config.json"}],
        lambda rows, oid: [{"new": "run:sha256:" + "0" * 64, "old": None, "ref": "heads/x"}],
        lambda rows, oid: [{"new": oid, "old": None, "ref": "heads/x", "extra": 1}],
        lambda rows, oid: [{"new": oid, "old": None, "ref": "heads/x"}] * 2,
        lambda rows, oid: [{"new": oid, "old": "nope", "ref": "heads/x"}],
        lambda rows, oid: "not a list",
    ],
)
def test_malformed_or_tampered_journals_are_rejected_not_applied(repo, mutate):
    a = _run(repo, "a")
    path = _journal(repo, mutate(None, a))
    _dead_lock(path.with_suffix(".lock"))
    repo.update_ref("heads/z", a)  # still writable: the bad journal stops blocking
    assert repo.read_ref("heads/x") is None
    assert not path.exists() and path.with_suffix(".rejected").exists()


def test_garbage_journal_bytes_are_rejected(repo):
    a = _run(repo, "a")
    directory = repo.path / "txn"
    directory.mkdir()
    (directory / ("b" * 32 + ".json")).write_bytes(b"\x00not json")
    repo.update_ref("heads/z", a)
    assert (directory / ("b" * 32 + ".rejected")).exists()


def test_a_crashed_writer_is_rolled_forward_after_kill(repo):
    a, b = _run(repo, "a"), _run(repo, "b")
    repo.update_refs([("heads/x", a, None), ("heads/y", a, None)])
    script = textwrap.dedent(
        f"""
        import os, signal, sys
        from opentine.repository import Repo
        from opentine.repository import _ref_txn as t
        original = t._write_ref
        def crash(*args):
            original(*args)
            if os.name == "nt":
                os._exit(9)
            os.kill(os.getpid(), signal.SIGKILL)
        t._write_ref = crash
        Repo({str(repo.path)!r}).update_refs(
            [("heads/x", {b!r}, {a!r}), ("heads/y", {b!r}, {a!r})]
        )
        """
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    result = subprocess.run([sys.executable, "-c", script], env=env, timeout=60)
    assert result.returncode != 0
    assert len(list((repo.path / "txn").glob("*.json"))) == 1  # died mid-update
    assert {repo.read_ref("heads/x"), repo.read_ref("heads/y")} == {a, b}  # half applied
    repo.update_ref("heads/unrelated", a)
    assert repo.read_ref("heads/x") == b and repo.read_ref("heads/y") == b
    assert not list((repo.path / "txn").glob("*"))


def test_a_crash_before_the_journal_rolls_back(repo):
    a, b = _run(repo, "a"), _run(repo, "b")
    repo.update_refs([("heads/x", a, None)])
    lock = repo.path / "refs" / "heads" / "x.lock"
    _dead_lock(lock)  # the crash left only a dead lock: nothing was committed
    repo.update_ref("heads/x", b, expected_old=a)
    assert repo.read_ref("heads/x") == b and not lock.exists()


def test_concurrent_pairs_stay_consistent(repo):
    runs = [_run(repo, str(index)) for index in range(12)]
    repo.update_refs([("heads/p", runs[0], None), ("heads/q", runs[0], None)])
    barrier = threading.Barrier(12)
    wins = []

    def worker(oid: str) -> None:
        barrier.wait()
        for _ in range(5):
            old_p, old_q = repo.read_ref("heads/p"), repo.read_ref("heads/q")
            try:
                repo.update_refs([("heads/p", oid, old_p), ("heads/q", oid, old_q)])
            except ValueError:
                continue
            wins.append(oid)
            return

    threads = [threading.Thread(target=worker, args=(oid,)) for oid in runs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert wins and repo.read_ref("heads/p") == repo.read_ref("heads/q") == wins[-1]


# -- rebase / cherry-pick --ref (0.12.1 review lows) ---------------------------------


def _cli_json(capsys, argv):
    capsys.readouterr()
    cli.main([*argv, "--json"])
    return json.loads(capsys.readouterr().out)


@pytest.fixture
def porcelain(repo, monkeypatch):
    monkeypatch.setattr(cli, "RUNS_DIR", Path(".tine_runs"))
    run = Run(id="base0001", model_info="m-old")
    for index in range(3):
        run.add_step(StepKind.model, {"text": str(index)}, {"text": "ok"})
    repo.put_run(run, ref="heads/main")
    return repo


@pytest.mark.parametrize(
    "argv",
    [
        ["rebase", "heads/main", "--onto-model", "m2", "--ref", "heads/keep"],
        ["cherry-pick", "heads/main:2", "--onto", "heads/main", "--ref", "heads/keep"],
    ],
)
def test_explicit_ref_is_not_overwritten_without_force(porcelain, capsys, argv):
    keep = _run(porcelain, "keep", ref="heads/keep")
    with pytest.raises(SystemExit):
        cli.main(argv)
    assert porcelain.read_ref("heads/keep") == keep
    moved = _cli_json(capsys, [*argv, "--force"])
    assert porcelain.read_ref("heads/keep") == moved["run_id"] != keep


def test_explicit_new_ref_needs_no_force(porcelain, capsys):
    out = _cli_json(capsys, ["rebase", "heads/main", "--onto-model", "m2", "--ref", "heads/n"])
    assert porcelain.read_ref("heads/n") == out["run_id"]


def test_recover_tolerates_journals_finished_after_listing(repo, monkeypatch):
    from opentine.repository._paths import internal_path

    directory = internal_path(repo.path, "txn")
    directory.mkdir(parents=True, exist_ok=True)
    gone = directory / f"{'a' * 32}.json"  # listed, then finished by its owner
    real = txn._journals
    listed = [[gone]]
    monkeypatch.setattr(txn, "_journals", lambda base: listed.pop() if listed else real(base))
    assert txn.recover(repo.path) == []
    assert not gone.with_suffix(".lock").exists()
    corrupt = directory / f"{'b' * 32}.json"
    corrupt.write_bytes(b"garbage")

    def vanished(src, dst):  # another recoverer rejected it first
        Path(src).unlink()
        raise FileNotFoundError(src)

    monkeypatch.setattr(txn.os, "replace", vanished)
    txn.recover(repo.path)  # no FileNotFoundError
    assert not corrupt.with_suffix(".lock").exists()
