"""Shared fixtures for the 0.85 scorer-isolation tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import opentine.cli as cli
from opentine.signing import generate_ed25519

GOOD = b"import helper\n\n\ndef score(output, item):\n    return helper.same(output, item)\n"
HELPER = b"def same(output, item):\n    return output == item['expected']\n"


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    seed, public = generate_ed25519()
    (tmp_path / "k.key").write_text(seed, encoding="utf-8", newline="\n")
    (tmp_path / "k.pub").write_text(public, encoding="utf-8", newline="\n")
    (tmp_path / "sc").mkdir()
    (tmp_path / "sc" / "good.py").write_bytes(GOOD)
    (tmp_path / "sc" / "helper.py").write_bytes(HELPER)
    rows = [{"id": f"i{n}", "input": str(n), "expected": str(n), "output": str(n % 3 and n),
             "run": "run:x"} for n in range(6)]  # fmt: skip
    data = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    (tmp_path / "d.jsonl").write_bytes(data.encode("utf-8"))
    return tmp_path


def code(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def run_json(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    status = code(*argv, "--json")
    return status, json.loads(capsys.readouterr().out)


def scorer(room: Path, name: str, body: str) -> str:
    """Write ``sc/<name>.py`` with *body* and return its ``python:`` spec."""
    (room / "sc" / f"{name}.py").write_bytes(body.encode("utf-8"))
    return f"python:sc/{name}.py:score"


def isolated_eval(capsys, room: Path, out: str = "ev", *extra: str) -> tuple[int, dict]:
    return run_json(capsys, "eval", "run", "d.jsonl", "--scorer", "python:sc/good.py:score",
                    "--isolate", "--key", "k.key", "--out", out, *extra)  # fmt: skip
