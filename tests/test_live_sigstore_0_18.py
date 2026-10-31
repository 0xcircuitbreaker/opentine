"""0.18 live check: refresh the public-good Sigstore trusted root over TUF.

Runs only with ``-m live`` (the weekly ``live-sigstore`` workflow); CI and the
release gate skip it. It bootstraps from root v5 of tuf-repo-cdn.sigstore.dev,
pinned here by digest, walks the real root chain, and parses the installed
trusted root, so a format change on Sigstore's side shows up before users hit it.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from opentine import cli
from opentine._trusted_root import parse_trusted_root

ROOT_V5 = Path(__file__).parent / "fixtures" / "sigstore" / "5.root.json"
ROOT_V5_SHA256 = "e2a930b2d1d4053dd56e8faf66fd113658545d522e35d222ccf58fea87ccccf4"


def test_the_pinned_bootstrap_root_is_intact() -> None:
    assert hashlib.sha256(ROOT_V5.read_bytes()).hexdigest() == ROOT_V5_SHA256


@pytest.mark.live
def test_update_installs_the_public_good_trusted_root(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr("sys.argv", ["tine", "trust", "root", "update", "--root", str(ROOT_V5)])
    try:
        cli.main()
    except SystemExit as exc:
        assert not exc.code, f"tine trust root update exited {exc.code}"
    installed = tmp_path / "xdg" / "opentine" / "sigstore" / "trusted_root.json"
    root = parse_trusted_root(installed.read_bytes())
    assert root.tlogs and root.authorities and root.ctlogs
