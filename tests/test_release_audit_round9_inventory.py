"""Round 9 release-audit regressions: the inventory gate must survive CRLF checkouts.

scripts/check_release_inventory.py hashes each tracked source out of the git
object database (`git show HEAD:<name>`, always the raw LF blob) and compares
those digests against the sdist, which hatchling builds from the *working
tree*.  windows-latest materializes CRLF by default (Git for Windows ships
core.autocrlf=true and actions/checkout does not override it), so without a
.gitattributes pinning working-tree bytes to blob bytes every text file
mismatches, ci.yml's Windows leg fails, and publish.yml's require-green-CI
step refuses the release.  These tests pin the whole class:

* .gitattributes exists and resolves every tracked file to a conversion-free
  checkout (eol=lf, or -text for verbatim binary/CRLF payloads);
* no tracked text blob contains a CR byte, so LF normalization can never
  churn content;
* the sdist include list ships .gitattributes itself (the inventory gate
  compares the sdist against `git ls-files`, so a tracked-but-not-shipped
  .gitattributes would fail as "missing");
* the gate still fails closed on EOL-only skew but now says so, and never
  blames real content drift on line endings.

The first two of those interrogate the repository itself with git.  ``tests`` is
shipped inside the sdist, so they must skip — loudly, with a reason — when the
tree they are running from is not a git checkout (a redistributor validating
opentine-0.3.0.tar.gz), instead of reporting ``fatal: not a git repository`` as
a content problem.  ``test_the_git_backed_checks_run_and_are_not_skipped_here``
in tests/test_release_audit_round10_lows.py keeps that skip from hiding a real
failure in CI, where the tests always run from a checkout.
"""

from __future__ import annotations

import hashlib
import io
import os
import subprocess
import tarfile
import tomllib
from pathlib import Path

import pytest

from scripts.check_release_inventory import InventoryError, _digest_pair, check_sdist

ROOT = Path(__file__).resolve().parents[1]


def is_checkout_root() -> bool:
    """True when ROOT is the top of a real git checkout (so git can be trusted).

    False for an unpacked sdist — including one unpacked *inside* some unrelated
    repository, where `git ls-files` would answer about that repository and the
    checks would silently pass on the wrong inventory.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"], capture_output=True
        )
    except OSError:  # git is not installed at all
        return False
    if result.returncode != 0:
        return False
    top = result.stdout.decode("utf-8", "replace").strip()
    try:
        return bool(top) and os.path.samefile(top, ROOT)
    except OSError:
        return False


requires_checkout = pytest.mark.skipif(
    not is_checkout_root(),
    reason=(
        f"{ROOT} is not a git checkout (an unpacked sdist ships these tests too); "
        "the .gitattributes/EOL guarantees are enforced by CI, which always runs "
        "from a checkout"
    ),
)


def _git(*args: str, data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", str(ROOT), *args], input=data, capture_output=True)


def _tracked() -> list[str]:
    result = _git("ls-files", "-z")
    assert result.returncode == 0, result.stderr.decode("utf-8")
    return [name.decode("utf-8") for name in result.stdout.split(b"\0") if name]


def _attributes(paths: list[str]) -> dict[str, dict[str, str]]:
    payload = b"\0".join(path.encode("utf-8") for path in paths) + b"\0"
    result = _git("check-attr", "--stdin", "-z", "text", "eol", data=payload)
    assert result.returncode == 0, result.stderr.decode("utf-8")
    fields = result.stdout.split(b"\0")
    resolved: dict[str, dict[str, str]] = {}
    for index in range(0, len(fields) - 2, 3):
        path, attribute, value = (field.decode("utf-8") for field in fields[index : index + 3])
        resolved.setdefault(path, {})[attribute] = value
    return resolved


@requires_checkout
def test_gitattributes_pins_every_tracked_file_to_a_conversion_free_checkout():
    assert (ROOT / ".gitattributes").is_file(), (
        ".gitattributes is required: without it windows-latest materializes CRLF "
        "(core.autocrlf=true) and the release inventory gate rejects every text "
        "file in the sdist, blocking ci.yml and therefore publish.yml"
    )
    tracked = sorted({*_tracked(), ".gitattributes"})
    unpinned = sorted(
        path
        for path, attrs in _attributes(tracked).items()
        # eol=lf checks out blob bytes verbatim; -text disables conversion
        # entirely (the documented escape hatch for genuine CRLF payloads).
        if attrs.get("eol") != "lf" and attrs.get("text") != "unset"
    )
    assert not unpinned, (
        "these tracked files can be materialized with CRLF on Windows checkouts, "
        "which the release inventory gate will reject; pin them in .gitattributes "
        f"(eol=lf, or -text for verbatim payloads): {unpinned}"
    )


@requires_checkout
def test_no_tracked_text_file_contains_a_carriage_return():
    result = _git("grep", "-I", "--name-only", "-e", "\r", "--", ".")
    assert result.returncode == 1 and not result.stdout, (
        "tracked text files contain CR bytes; '* text=auto eol=lf' would rewrite "
        "them on the next commit (content churn) — either normalize them to LF or "
        "mark them -text in .gitattributes and exempt them here: " + result.stdout.decode("utf-8")
    )


def test_sdist_include_list_ships_gitattributes():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    include = data["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    assert "/.gitattributes" in include, (
        "the sdist is built from an explicit include list; once .gitattributes is "
        "tracked, the inventory gate requires it inside the sdist ('missing: "
        ".gitattributes' otherwise)"
    )


def _sdist(path: Path, entries: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, body in entries.items():
            member = tarfile.TarInfo(f"opentine-0.3.0/{name}")
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))


def test_eol_only_sdist_mismatch_still_fails_but_names_line_ending_skew(tmp_path: Path):
    path = tmp_path / "opentine-0.3.0.tar.gz"
    source = {"README.md": hashlib.sha256(b"line one\nline two\n").digest()}
    _sdist(path, {"README.md": b"line one\r\nline two\r\n", "PKG-INFO": b"meta"})
    with pytest.raises(InventoryError, match="sdist content differs from source") as info:
        check_sdist(path, {"README.md"}, "opentine", "0.3.0", source_hashes=source)
    message = str(info.value)
    assert "1 of 1 differ only in CRLF vs LF line endings" in message
    assert ".gitattributes" in message


def test_real_content_drift_is_never_blamed_on_line_endings(tmp_path: Path):
    path = tmp_path / "opentine-0.3.0.tar.gz"
    source = {"README.md": hashlib.sha256(b"reviewed\n").digest()}
    _sdist(path, {"README.md": b"tampered\n", "PKG-INFO": b"meta"})
    with pytest.raises(InventoryError, match="sdist content differs from source") as info:
        check_sdist(path, {"README.md"}, "opentine", "0.3.0", source_hashes=source)
    assert "line endings" not in str(info.value)


def test_mixed_drift_reports_only_the_eol_only_subset(tmp_path: Path):
    path = tmp_path / "opentine-0.3.0.tar.gz"
    source = {
        "README.md": hashlib.sha256(b"reviewed\n").digest(),
        "LICENSE": hashlib.sha256(b"terms\n").digest(),
    }
    _sdist(
        path,
        {"README.md": b"tampered\n", "LICENSE": b"terms\r\n", "PKG-INFO": b"meta"},
    )
    with pytest.raises(InventoryError, match="LICENSE, README.md") as info:
        check_sdist(path, {"README.md", "LICENSE"}, "opentine", "0.3.0", source_hashes=source)
    assert "1 of 2 differ only in CRLF vs LF line endings" in str(info.value)


def test_digest_pair_normalizes_crlf_across_any_chunk_boundary():
    body = b"alpha\r\nbravo\r\ncharlie\r"
    raw_expected = hashlib.sha256(body).digest()
    normalized_expected = hashlib.sha256(b"alpha\nbravo\ncharlie\r").digest()
    for chunk_size in (1, 2, 3, 7, len(body), 1024):
        raw, normalized = _digest_pair(io.BytesIO(body), chunk_size)
        assert raw == raw_expected, chunk_size
        assert normalized == normalized_expected, chunk_size
    # a lone CR that is not part of CRLF is content, not a line ending
    raw, normalized = _digest_pair(io.BytesIO(b"a\rb"), 1)
    assert raw == hashlib.sha256(b"a\rb").digest()
    assert normalized == hashlib.sha256(b"a\rb").digest()
