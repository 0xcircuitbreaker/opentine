"""A committed v3 repository is a version-control artifact, not just a store.

The cross-version gate in ``tests/test_backwards_compat.py`` reads golden v3
repositories straight out of git. git and tar drop empty directories, and an
archived or containerised checkout may be read-only, so ``Repo.open`` must
reconstitute the layout where it can and degrade cleanly where it cannot.
Without this, every committed compat fixture would be unopenable.
"""

from __future__ import annotations


def test_a_repository_that_lost_its_empty_dirs_to_version_control_still_opens(tmp_path):
    """git and tar drop empty directories, so a v3 repo committed to version
    control loses packs/, indexes/, logs/ and the empty refs/* namespaces. Open
    must recreate them rather than leave the repo unusable and fsck failing."""
    from opentine.repository import Repo

    repo = Repo.init(tmp_path / "src")
    oid = repo.put("blob", b"survives version control", redact=False)
    tine = tmp_path / "src" / ".tine"
    stripped = sorted(
        p.relative_to(tine).as_posix()
        for p in tine.rglob("*")
        if p.is_dir() and not any(p.iterdir())
    )
    assert {"packs", "indexes", "logs"} <= set(stripped)
    for name in stripped:
        (tine / name).rmdir()

    reopened = Repo.open(tmp_path / "src")
    assert reopened.fsck().ok
    assert reopened.get(oid).body == b"survives version control"
    for name in stripped:
        assert (tine / name).is_dir()


def test_a_read_only_repository_missing_empty_dirs_still_opens(tmp_path):
    """Recreating the dropped layout on open must be best-effort: a repository on
    read-only media (a container layer, a read-only mount, an archived checkout)
    cannot be healed, but its objects and refs are still readable, so opening
    must degrade rather than crash."""
    import os
    import stat

    from opentine.repository import Repo

    repo = Repo.init(tmp_path / "src")
    oid = repo.put("blob", b"readable on read-only media", redact=False)
    tine = tmp_path / "src" / ".tine"
    for directory in [p for p in tine.rglob("*") if p.is_dir() and not any(p.iterdir())]:
        directory.rmdir()
    for path in sorted(tine.rglob("*"), reverse=True):
        if path.is_file():
            os.chmod(path, stat.S_IRUSR)
    os.chmod(tine, stat.S_IRUSR | stat.S_IXUSR)
    try:
        reopened = Repo.open(tmp_path / "src")
        assert reopened.get(oid).body == b"readable on read-only media"
        # Verification must also degrade cleanly: packs/ ships empty, so version
        # control drops it and read-only media cannot heal it back. An absent
        # packs/ holds nothing to verify — deep fsck must not flunk the repo.
        report = reopened.fsck(deep=True)
        assert report.ok, f"healthy read-only repository must verify clean, got {report.errors}"
    finally:
        for path in [tine, *tine.rglob("*")]:
            os.chmod(path, stat.S_IRWXU)
