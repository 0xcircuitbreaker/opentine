"""A lock mid-publish has two names; the hard-link guard must not mistake it.

``acquire`` links an already-stamped temp file onto the lock name, so a
contender can see the lock with two links (and keeps seeing it if Windows
refuses to remove the temp name). That read as "repository path contains a
hard-linked file" and failed a concurrent gc instead of reporting the lock.
"""

from __future__ import annotations

import os

import pytest

from opentine.kernel import KernelError
from opentine.repository import Repo, _lockfile
from opentine.repository._gc import gc_lock
from opentine.repository._paths import internal_path


def _link(src, dst):
    try:
        os.link(src, dst)
    except OSError:
        pytest.skip("hard links unsupported here")


def _published_but_not_tidied(lock):
    """The state between a contender's link and its temp-name removal."""
    tmp = lock.with_name(lock.name + ".new-1-2-3..lock")
    tmp.write_bytes(_lockfile.stamp())
    _link(tmp, lock)
    return tmp


def test_a_lock_with_its_temp_name_still_present_is_reported_as_held(tmp_path):
    repo = Repo.init(tmp_path / "r")
    _published_but_not_tidied(repo.path / "gc.lock")
    with pytest.raises(KernelError, match="another tine gc is running"):
        with gc_lock(repo.path):
            pass


def test_two_links_are_allowed_only_on_a_lock_name(tmp_path):
    repo = Repo.init(tmp_path / "r")
    lock = repo.path / "gc.lock"
    _published_but_not_tidied(lock)
    assert internal_path(repo.path, "gc.lock") == repo.path / "gc.lock"
    _link(lock, tmp_path / "third")  # a third name is never ours
    with pytest.raises(KernelError, match="hard-linked"):
        internal_path(repo.path, "gc.lock")


def test_any_other_file_with_two_links_is_still_refused(tmp_path):
    repo = Repo.init(tmp_path / "r")
    outside = tmp_path / "outside"
    outside.write_bytes(b"x")
    _link(outside, repo.path / "config.extra")
    with pytest.raises(KernelError, match="hard-linked"):
        internal_path(repo.path, "config.extra")
