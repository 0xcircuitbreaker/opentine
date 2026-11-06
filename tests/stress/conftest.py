"""Nightly stress tests: collected always, run only when asked.

They take minutes, so the default ``pytest`` run (and the per-PR CI job, which
selects ``-m "not live and not live_harness"``) skips them. Run them with
``OPENTINE_STRESS=1 uv run pytest tests/stress -m stress`` (the nightly
workflow does this) or select them with ``-m stress``.
"""

from __future__ import annotations

import os

import pytest


def _wanted(config: pytest.Config) -> bool:
    if os.environ.get("OPENTINE_STRESS") == "1":
        return True
    expr = (config.getoption("markexpr") or "").replace(" ", "")
    return "stress" in expr and "notstress" not in expr


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _wanted(config):
        return
    skip = pytest.mark.skip(reason="stress test: set OPENTINE_STRESS=1 or pass -m stress")
    here = os.path.dirname(__file__)
    for item in items:
        if str(item.path).startswith(here):
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
