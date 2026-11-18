"""A comparison that does not verify is a refusal, never a silent pass."""

from __future__ import annotations

from pathlib import Path

from opentine import _eval_compare, _promote_checks


def test_an_unverified_comparison_refuses(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_eval_compare, "statistical", lambda *a, **k: {"ok": False, "stats": None})
    policy = {"test": "permutation", "alpha": "0.05", "seed": 0, "resamples": 100}
    out: list = []
    assert _promote_checks._beats("main", tmp_path, tmp_path, policy, out) is None
    assert [r["code"] for r in out] == ["promote.eval-invalid"]
