"""0.13: Windows sharing violations on ref, lock, journal and root files.

Windows refuses to rename over, delete, or reopen (while delete-pending) a file
another handle has open; Python never opens with ``FILE_SHARE_DELETE``, so an
unlocked reader makes a writer's ``os.replace``/``unlink`` fail with
``PermissionError``. These tests simulate that on any OS by making the calls
fail N times with ``_winretry.WINDOWS`` forced on.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine.repository import Repo, _winretry
from opentine.repository import _ref_txn as txn
from opentine.repository._lockfile import acquire, stamp
from opentine.repository._prune_roots import UnsafePlan, file_roots

_real_replace, _real_unlink, _real_open = os.replace, os.unlink, os.open


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(_winretry, "WINDOWS", True)
    monkeypatch.setattr(_winretry, "_sleep", lambda _seconds: None)
    return Repo.init(tmp_path)


def _run(store: Repo, label: str, ref: str | None = None) -> str:
    run = Run(id=f"r{label}", model_info="m")
    run.add_step(StepKind.model, {"text": label}, {"text": "ok"})
    return store.put_run(run, ref=ref).run_id


def _flaky(real, match, times):
    """``real``, raising a sharing violation ``times`` times when the path matches."""
    left = {"n": times}

    def call(path, *args, **kwargs):
        target = str(args[0]) if real is _real_replace else str(path)
        if match(target) and left["n"] != 0:
            left["n"] -= 1
            raise PermissionError(32, "being used by another process", target)
        return real(path, *args, **kwargs)

    return call, left


def _named(name: str):
    return lambda path: Path(path).name == name


def test_transaction_survives_a_transient_replace_violation_after_commit(repo, monkeypatch):
    # CI regression: q's replace failed after p was written (WinError 5), leaving
    # the pair half-applied until some later write rolled the journal forward.
    a, b = _run(repo, "a"), _run(repo, "b")
    repo.update_refs([("heads/p", a, None), ("heads/q", a, None)])
    flaky, left = _flaky(_real_replace, _named("q"), 5)
    monkeypatch.setattr(os, "replace", flaky)
    repo.update_refs([("heads/p", b, a), ("heads/q", b, a)])
    assert left["n"] == 0
    assert repo.read_ref("heads/p") == repo.read_ref("heads/q") == b
    assert not list((repo.path / "txn").iterdir())


def test_a_persistent_violation_after_commit_rolls_forward_on_the_next_write(repo, monkeypatch):
    a, b, c = _run(repo, "a"), _run(repo, "b"), _run(repo, "c")
    repo.update_refs([("heads/p", a, None), ("heads/q", a, None)])
    flaky, _ = _flaky(_real_replace, _named("q"), -1)
    monkeypatch.setattr(os, "replace", flaky)
    with pytest.raises(PermissionError):
        repo.update_refs([("heads/p", b, a), ("heads/q", b, a)])
    monkeypatch.setattr(os, "replace", _real_replace)
    # Locks are released (fail closed, but not wedged); the journal is pending.
    assert not list(repo.path.glob("refs/heads/*.lock"))
    assert txn.pending(repo.path)
    repo.update_refs([("heads/r", c, None)])  # any write rolls it forward first
    assert repo.read_ref("heads/p") == repo.read_ref("heads/q") == b


def test_lock_release_outlasts_a_contender_reading_the_lock(repo, monkeypatch):
    a, b = _run(repo, "a"), _run(repo, "b")
    repo.update_refs([("heads/p", a, None), ("heads/q", a, None)])
    flaky, left = _flaky(_real_unlink, _named("p.lock"), 6)
    monkeypatch.setattr(os, "unlink", flaky)
    repo.update_refs([("heads/p", b, a), ("heads/q", b, a)])
    assert left["n"] == 0 and not list(repo.path.glob("**/*.lock"))
    repo.update_refs([("heads/p", a, b), ("heads/q", a, b)])  # not wedged


def test_a_stuck_lock_does_not_strand_the_others(repo, monkeypatch):
    a = _run(repo, "a")
    flaky, _ = _flaky(_real_unlink, _named("p.lock"), -1)
    monkeypatch.setattr(os, "unlink", flaky)
    with pytest.raises(PermissionError):
        repo.update_refs([("heads/p", a, None), ("heads/q", a, None)])
    assert repo.read_ref("heads/p") == repo.read_ref("heads/q") == a
    left = sorted(path.name for path in repo.path.glob("**/*.lock"))
    assert left == ["p.lock"]


def test_single_ref_commit_retries_replace_and_lock_unlink(repo, monkeypatch):
    a = _run(repo, "a", ref="heads/live")
    replace, replaces = _flaky(_real_replace, _named("live"), 4)
    unlink, unlinks = _flaky(_real_unlink, _named("live.lock"), 4)
    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(os, "unlink", unlink)
    b = _run(repo, "b", ref="heads/live")
    assert replaces["n"] == unlinks["n"] == 0 and a != b
    assert repo.read_ref("heads/live") == b
    assert not (repo.path / "refs/heads/live.lock").exists()


def test_ref_read_retries_a_delete_pending_open(repo, monkeypatch):
    a = _run(repo, "a", ref="heads/live")
    flaky, left = _flaky(_real_open, _named("live"), 5)
    monkeypatch.setattr(os, "open", flaky)
    assert repo.read_ref("heads/live") == a and left["n"] == 0


def test_a_real_denial_is_not_retried_off_windows(repo, monkeypatch):
    _run(repo, "a", ref="heads/live")
    monkeypatch.setattr(_winretry, "WINDOWS", False)
    flaky, left = _flaky(_real_open, _named("live"), 5)
    monkeypatch.setattr(os, "open", flaky)
    with pytest.raises(PermissionError):
        repo.read_ref("heads/live")
    assert left["n"] == 4


def test_prune_root_scan_retries_then_fails_closed(repo, monkeypatch):
    a = _run(repo, "a", ref="heads/live")
    real_open = open

    def flaky_open(path, *args, **kwargs):
        if Path(path).name == "live" and state["n"] != 0:
            state["n"] -= 1
            raise PermissionError(13, "Permission denied", str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", flaky_open)
    state = {"n": 5}
    assert a in file_roots(repo.path)
    state["n"] = -1
    with pytest.raises(UnsafePlan, match="cannot read root file live"):
        file_roots(repo.path)


def test_a_dead_lock_held_open_by_a_contender_is_reported_not_crashed(tmp_path, monkeypatch):
    monkeypatch.setattr(_winretry, "WINDOWS", True)
    monkeypatch.setattr(_winretry, "_sleep", lambda _seconds: None)
    lock = tmp_path / "x.lock"
    lock.write_bytes(stamp().replace(str(os.getpid()).encode(), b"999999999", 1))

    def rename(*args):
        raise PermissionError(32, "being used by another process")

    monkeypatch.setattr(os, "rename", rename)
    with pytest.raises(FileExistsError):
        acquire(lock)
    assert lock.exists()


def test_retry_is_bounded(monkeypatch):
    monkeypatch.setattr(_winretry, "WINDOWS", True)
    naps: list[float] = []
    monkeypatch.setattr(_winretry, "_sleep", naps.append)
    calls = []

    def denied():
        calls.append(1)
        raise PermissionError(5, "Access is denied")

    with pytest.raises(PermissionError):
        _winretry.retry(denied)
    assert len(calls) == _winretry.ATTEMPTS and 1 < sum(naps) < 5


def test_containment_check_retries_a_transient_resolve_denial(repo, monkeypatch):
    from opentine.repository._paths import internal_path

    real_resolve, calls = Path.resolve, []

    def flaky(self, strict=False):
        calls.append(self)
        if len(calls) <= 2:
            raise PermissionError(13, "delete pending")
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", flaky)
    assert internal_path(repo.path, "refs") == repo.path / "refs"
    assert len(calls) > 2


def test_a_persistent_resolve_denial_is_not_reported_as_an_escape(repo, monkeypatch):
    from opentine.kernel import KernelError
    from opentine.repository._paths import internal_path

    def denied(self, strict=False):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(Path, "resolve", denied)
    with pytest.raises(KernelError, match="cannot be inspected"):
        internal_path(repo.path, "refs")


def test_an_extended_length_resolve_is_the_same_path_not_an_escape(repo, monkeypatch):
    # Python 3.11 on Windows: realpath of a file mid-replace returns \\?\C:\...
    from opentine.repository._paths import internal_path

    real_resolve = Path.resolve

    def extended(self, strict=False):
        resolved = real_resolve(self, strict=strict)
        return resolved if self == repo.path else Path("\\\\?\\" + str(resolved))

    monkeypatch.setattr(Path, "resolve", extended)
    assert internal_path(repo.path, "refs") == repo.path / "refs"


def test_an_extended_unc_resolve_still_fails_closed(repo, monkeypatch):
    from opentine.kernel import KernelError
    from opentine.repository._paths import internal_path

    real_resolve = Path.resolve

    def unc(self, strict=False):
        resolved = real_resolve(self, strict=strict)
        return resolved if self == repo.path else Path("\\\\?\\UNC\\host\\share\\x")

    monkeypatch.setattr(Path, "resolve", unc)
    with pytest.raises(KernelError, match="escapes its root"):
        internal_path(repo.path, "refs")


def test_a_pack_index_unreadable_for_a_moment_is_not_hidden_for_good(tmp_path, monkeypatch):
    from opentine.repository import _packs
    from opentine.repository._gc import gc

    monkeypatch.setattr(_winretry, "WINDOWS", False)  # no retry: the next lookup must recover
    store = Repo.init(tmp_path)
    oid = store.put("blob", b"packed")
    gc(store, min_age=0)
    real_load, failures = _packs.load_index, []

    def once(root, digest):
        if not failures:
            failures.append(digest)
            raise PermissionError(13, "being renamed in")
        return real_load(root, digest)

    monkeypatch.setattr(_packs, "load_index", once)
    packs = _packs.PackSet(store.path)
    assert packs.locate(oid) is not None  # the miss rescans instead of caching the gap
    assert failures
