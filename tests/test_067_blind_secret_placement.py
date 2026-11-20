"""0.67: the blind-audit opening is kept out of the repository the auditor can read."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from opentine import cli
from opentine.repository import Repo

FIXTURES = Path(__file__).parent / "fixtures" / "petri"


def _tine(capsys, *argv: str) -> tuple[int, dict, str]:
    capsys.readouterr()
    try:
        cli.main([*argv, "--json"])
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    out = captured.out
    return code, (json.loads(out) if out.strip() else {}), captured.err + out


@pytest.fixture
def room(tmp_path, monkeypatch):
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    Repo.init(tmp_path / "r")
    return tmp_path


def _import(capsys, tmp: Path, secret: Path, *extra: str) -> tuple[int, dict, str]:
    return _tine(capsys, "auditor", "import-petri", str(FIXTURES / "transcript.json"),
                 "--repo", str(tmp / "r"), "--blind", str(secret), *extra)  # fmt: skip


def test_a_secret_inside_the_repository_is_refused(room, capsys):
    secret = room / "r" / "secret.json"
    code, _, text = _import(capsys, room, secret)
    assert code != 0 and "inside the repository" in text
    assert not secret.exists()


def test_a_secret_under_the_store_directory_is_refused(room, capsys):
    store = room / "r" / ".tine"
    target = (store if store.is_dir() else room / "r") / "opening.json"
    code, _, _ = _import(capsys, room, target)
    assert code != 0 and not target.exists()


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_symlinked_directory_into_the_repository_is_refused(room, capsys):
    link = room / "outside"
    link.symlink_to(room / "r", target_is_directory=True)
    code, _, _ = _import(capsys, room, link / "secret.json")
    assert code != 0 and not (room / "r" / "secret.json").exists()


def test_allow_in_repo_opts_in(room, capsys):
    secret = room / "r" / "secret.json"
    code, out, _ = _import(capsys, room, secret, "--allow-in-repo")
    assert code == 0 and out["sealed"] and secret.exists()


def test_an_existing_secret_file_is_not_overwritten(room, capsys):
    secret = room / "secret.json"
    secret.write_bytes(b"keep\n")
    code, _, text = _import(capsys, room, secret)
    assert code != 0 and "exists" in text
    assert secret.read_bytes() == b"keep\n"


def test_a_secret_outside_the_repository_is_written(room, capsys):
    secret = room / "secret.json"
    code, out, _ = _import(capsys, room, secret)
    assert code == 0 and out["sealed"]
    assert json.loads(secret.read_bytes())["nonce"]
