"""0.12.1 regressions: crash-safe ref/gc locks and ``rev:path`` containment."""

from __future__ import annotations

import os

import pytest

from opentine import Repo, Run, StepKind
from opentine.kernel import KernelError
from opentine.repository import _lockfile
from opentine.repository._gc import gc_lock
from opentine.tools._git_guard import refusal

#: A fake repository-top marker in a temp dir (no checkout, no git binary);
#: spelled so the checkout-awareness meta-test does not mistake it for one.
GIT_MARKER = "." + "git"


def _run(name: str) -> Run:
    run = Run(id=name)
    run.add_step(StepKind.model, {"prompt": name}, {"out": "y"})
    return run


def _repo(tmp_path) -> Repo:
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run("patch-0121"), ref="heads/main")
    return repo


def _other(repo: Repo) -> str:
    return repo.put_run(_run("other")).run_id


def _ref_lock(repo: Repo):
    return repo.path / "refs" / "heads" / "main.lock"


# -- 1. ref lock left by a crashed writer --------------------------------------


def test_a_ref_lock_from_a_dead_writer_on_this_host_is_recovered(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    old = repo.read_ref("heads/main")
    lock = _ref_lock(repo)
    lock.write_bytes(f"424242 {_lockfile._host()} 0\n".encode())
    monkeypatch.setattr(_lockfile, "pid_alive", lambda pid: pid != 424242)
    new = _other(repo)
    repo.update_ref("heads/main", new, expected_old=old)
    assert repo.read_ref("heads/main") == new
    assert not lock.exists()
    assert not [p for p in lock.parent.iterdir() if "stale" in p.name]


@pytest.mark.parametrize(
    "content",
    [
        lambda: f"{os.getpid()} {_lockfile._host()} 0\n",  # live process
        lambda: "424242 some-other-host 0\n",  # another host: cannot prove dead
        lambda: "",  # 0.12.0 empty lock, or a crash before the stamp
        lambda: "garbage",
    ],
)
def test_a_lock_that_is_not_provably_dead_is_kept_and_named(tmp_path, monkeypatch, content):
    repo = _repo(tmp_path)
    old = repo.read_ref("heads/main")
    lock = _ref_lock(repo)
    lock.write_text(content(), encoding="ascii")
    monkeypatch.setattr(_lockfile, "pid_alive", lambda pid: pid == os.getpid())
    with pytest.raises(ValueError, match="main.lock") as caught:
        repo.update_ref("heads/main", _other(repo), expected_old=old)
    assert "delete that file" in str(caught.value)
    assert lock.exists() and repo.read_ref("heads/main") == old


def test_a_crash_mid_write_releases_the_ref_lock(tmp_path, monkeypatch):
    from opentine.repository import _ref_store

    repo = _repo(tmp_path)
    old = repo.read_ref("heads/main")

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(_ref_store, "append_reflog", boom)
    with pytest.raises(OSError):
        repo.update_ref("heads/main", _other(repo), expected_old=old)
    assert not _ref_lock(repo).exists()


def test_the_lock_records_pid_host_and_time(tmp_path):
    path = tmp_path / "x.lock"
    os.close(_lockfile.acquire(path))
    pid, host, when = path.read_text(encoding="ascii").split()
    assert int(pid) == os.getpid() and host == _lockfile._host() and int(when) > 0


def test_this_process_counts_as_alive():
    assert _lockfile.pid_alive(os.getpid())


# -- 3. gc lock: liveness, never age -------------------------------------------


def test_an_old_gc_lock_of_a_live_process_is_not_broken(tmp_path):
    repo = _repo(tmp_path)
    (repo.path / "gc.lock").write_text(f"{os.getpid()} 0\n", encoding="ascii")  # ancient
    with pytest.raises(KernelError, match="gc.lock"):
        with gc_lock(repo.path):
            pass


def test_a_dead_same_host_gc_lock_is_taken_over(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    lock = repo.path / "gc.lock"
    lock.write_text(f"424242 {_lockfile._host()} {10**9}\n", encoding="ascii")
    monkeypatch.setattr(_lockfile, "pid_alive", lambda pid: False)
    with gc_lock(repo.path):
        assert lock.read_text(encoding="ascii").startswith(f"{os.getpid()} ")
    assert not lock.exists()


def test_the_gc_break_override_still_works(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    (repo.path / "gc.lock").write_text(f"{os.getpid()} x 0\n", encoding="ascii")
    monkeypatch.setenv("OPENTINE_GC_BREAK_LOCK", "1")
    with gc_lock(repo.path):
        pass


# -- 4. rev:path is resolved by git from the repository top --------------------


@pytest.fixture
def subdir_root(tmp_path):
    (tmp_path / GIT_MARKER).mkdir()  # repository top above the shell root
    root = tmp_path / "pkg"
    (root / "src").mkdir(parents=True)
    return root


@pytest.mark.parametrize("token", ["HEAD:secret.txt", "HEAD:", "main:other/file", "HEAD:pkg/../x"])
def test_top_relative_rev_path_outside_a_subdir_root_is_refused(subdir_root, token):
    assert refusal(["show", token], root=subdir_root)


@pytest.mark.parametrize("token", ["HEAD:pkg/src/a.py", "HEAD:./src/a.py", "HEAD:pkg", "HEAD~1"])
def test_rev_path_inside_a_subdir_root_still_works(subdir_root, token):
    assert refusal(["show", token], root=subdir_root) is None


def test_rev_path_at_the_repository_top_is_unchanged(tmp_path):
    (tmp_path / GIT_MARKER).mkdir()
    assert refusal(["show", "HEAD:secret.txt"], root=tmp_path) is None
    assert refusal(["show", "HEAD:"], root=tmp_path) is None
