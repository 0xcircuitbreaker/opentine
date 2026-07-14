"""CLI coverage for signed pricing and v3 repository commands."""

from __future__ import annotations

import sys
from pathlib import Path

from opentine import Repo, cli
from opentine.billing.catalog import BUNDLED_CATALOG

FIXTURES = Path(__file__).parent / "fixtures"


def _invoke(monkeypatch, *args: str) -> None:
    monkeypatch.setattr(sys, "argv", ["tine", *args])
    cli.main()


def test_pricing_lifecycle_commands(monkeypatch, tmp_path, capsys):
    _invoke(monkeypatch, "pricing", "check")
    assert "signed" in capsys.readouterr().out
    _invoke(monkeypatch, "pricing", "show", "kimi", "kimi-k2.6")
    assert "chat-k26" in capsys.readouterr().out
    _invoke(monkeypatch, "pricing", "list", "--provider", "mistral")
    listing = capsys.readouterr().out
    assert "Pricing catalog" in listing and "mistral" in listing

    installed = tmp_path / "catalog.json"
    _invoke(
        monkeypatch,
        "pricing",
        "update",
        str(BUNDLED_CATALOG),
        "--dest",
        str(installed),
    )
    assert installed.is_file()
    _invoke(monkeypatch, "pricing", "check", str(installed))
    assert "OK" in capsys.readouterr().out


def test_repository_init_migrate_inspect_pack_and_fsck(monkeypatch, tmp_path, capsys):
    worktree = tmp_path / "repo"
    _invoke(monkeypatch, "init", str(worktree))
    repo = Repo.open(worktree)
    oid = repo.put("blob", b"cli-object", redact=False)

    _invoke(monkeypatch, "object", oid, "--repo", str(worktree))
    assert oid in capsys.readouterr().out
    output = tmp_path / "objects.pack"
    _invoke(monkeypatch, "pack", "--repo", str(worktree), "--output", str(output))
    assert output.read_bytes().startswith(b"TINEPACK3\0")

    _invoke(
        monkeypatch,
        "migrate-v3",
        str(FIXTURES / "golden_v2.tine"),
        "--repo",
        str(worktree),
        "--ref",
        "heads/imported",
    )
    assert repo.read_ref("heads/imported").startswith("run:sha256:")
    _invoke(monkeypatch, "repo-log", "heads/imported", "--repo", str(worktree))
    assert "event:sha256:" in capsys.readouterr().out
    _invoke(monkeypatch, "fsck", "--repo", str(worktree))
    assert '"ok": true' in capsys.readouterr().out
