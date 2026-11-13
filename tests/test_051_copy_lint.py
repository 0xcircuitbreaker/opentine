"""The overclaim docs lint (``scripts/check_copy.py``, 0.51) passes on the tree and catches hits."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _lint():
    spec = importlib.util.spec_from_file_location("check_copy", ROOT / "scripts" / "check_copy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_docs_are_clean() -> None:
    lint = _lint()
    assert lint.hits() == []
    assert lint.main([]) == 0


def test_every_banned_phrase_is_caught_case_insensitively(tmp_path: Path) -> None:
    lint = _lint()
    (tmp_path / "docs" / "deep").mkdir(parents=True)
    (tmp_path / "README.md").write_text("OpenTine gives VERIFIED Execution.\n", "utf-8")
    body = "ok\nGenuine model output and unique\nline-level attribution.\n"
    (tmp_path / "docs" / "deep" / "a.md").write_text(body, "utf-8")
    (tmp_path / "docs" / "b.md").write_text("This Proves The Model; only line-level attribution\n")
    (tmp_path / "docs" / "ROADMAP.md").write_text("verified execution is banned\n", "utf-8")
    found = lint.hits(tmp_path)
    assert {(p, phrase.lower()) for p, _, phrase in found} == {
        ("README.md", "verified execution"),
        ("docs/deep/a.md", "genuine model output"),
        ("docs/deep/a.md", "unique line-level attribution"),
        ("docs/b.md", "proves the model"),
        ("docs/b.md", "only line-level attribution"),
    }
    assert ("docs/deep/a.md", 2) in {(p, line) for p, line, _ in found}


def test_hex_digests_and_neighbouring_words_do_not_fire(tmp_path: Path) -> None:
    lint = _lint()
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("sha256 " + "ab" * 32 + "\n", "utf-8")
    text = "the run was verified; execution logs; the model proves nothing\n"
    (tmp_path / "docs" / "x.md").write_text(text, "utf-8")
    assert lint.hits(tmp_path) == []


def test_ci_runs_the_lint() -> None:
    workflows = (ROOT / ".github" / "workflows").glob("*.yml")
    assert any("scripts/check_copy.py" in p.read_text("utf-8") for p in workflows)
