"""Streaming autosave + draft-marker coverage."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from opentine import Run, StepKind
from opentine.autosave import Autosaver
from opentine.core import RunStatus
from opentine.runtime import Agent

# --- draft marker -----------------------------------------------------------


def test_draft_save_marks_and_verifies(tmp_path: Path):
    run = Run(id="x")
    run.add_step(StepKind.think, {"text": "wip"})
    p = run.save(tmp_path / "d.tine", draft=True)
    data = json.loads(p.read_text())
    assert data["draft"] is True
    assert data["metadata"]["autosave"]["partial"] is True
    result = Run.verify_integrity(p)
    assert result.ok and result.draft is True


def test_final_save_has_no_draft(tmp_path: Path):
    run = Run(id="x")
    run.add_step(StepKind.done, {"text": "ok"})
    p = run.save(tmp_path / "f.tine")
    data = json.loads(p.read_text())
    assert "draft" not in data
    assert "autosave" not in data["metadata"]
    assert Run.verify_integrity(p).draft is False
    # saving a draft never mutated the run's own metadata
    assert "autosave" not in run.metadata


def test_draft_digest_differs_from_final(tmp_path: Path):
    run = Run(id="x")
    run.add_step(StepKind.done, {"text": "ok"})
    final = json.loads(run.save(tmp_path / "f.tine").read_text())
    draft = json.loads(run.save(tmp_path / "d.tine", draft=True).read_text())
    # the draft flag is inside the digest, so the digests differ
    assert final["metadata"]["integrity"]["digest"] != draft["metadata"]["integrity"]["digest"]


# --- Autosaver throttle -----------------------------------------------------


def test_autosaver_and_throttle_by_steps(tmp_path: Path):
    run = Run(id="x")
    saver = Autosaver(tmp_path / "a.tine", every_n_steps=2)
    run.add_step(StepKind.think, {"text": "1"})
    assert saver.maybe_save(run) is False  # 1 < 2
    run.add_step(StepKind.think, {"text": "2"})
    assert saver.maybe_save(run) is True
    run.add_step(StepKind.think, {"text": "3"})
    assert saver.maybe_save(run) is False  # only 1 since last save
    run.add_step(StepKind.think, {"text": "4"})
    assert saver.maybe_save(run) is True


def test_autosaver_disabled_without_gates(tmp_path: Path):
    run = Run(id="x")
    run.add_step(StepKind.think, {"text": "1"})
    saver = Autosaver(tmp_path / "a.tine")
    assert saver.enabled is False
    assert saver.maybe_save(run) is False
    assert not (tmp_path / "a.tine").exists()


def test_autosaver_requires_both_gates(tmp_path: Path):
    run = Run(id="x")
    run.add_step(StepKind.think, {"text": "1"})
    # step gate satisfied immediately, but the 1000s gate suppresses the write
    saver = Autosaver(tmp_path / "a.tine", every_n_steps=1, every_seconds=1000)
    assert saver.maybe_save(run) is False


def test_flush_finalizes_terminal_run(tmp_path: Path):
    run = Run(id="x")
    run.add_step(StepKind.done, {"text": "ok"})
    run.status = RunStatus.completed
    saver = Autosaver(tmp_path / "a.tine", every_n_steps=1)
    saver.maybe_save(run, force=True)
    assert json.loads((tmp_path / "a.tine").read_text())["draft"] is True
    saver.flush(run)
    data = json.loads((tmp_path / "a.tine").read_text())
    assert "draft" not in data
    assert Run.verify_integrity(tmp_path / "a.tine").draft is False


def test_resaving_loaded_draft_strips_autosave(tmp_path: Path):
    run = Run(id="x")
    run.add_step(StepKind.done, {"text": "ok"})
    run.status = RunStatus.completed
    draft_path = run.save(tmp_path / "d.tine", draft=True)
    assert "autosave" in json.loads(draft_path.read_text())["metadata"]

    # Loading a draft carries metadata.autosave; a final re-save must drop it.
    loaded = Run.load(draft_path)
    final = loaded.save(tmp_path / "f.tine")
    data = json.loads(final.read_text())
    assert "draft" not in data
    assert "autosave" not in data["metadata"]


def test_flush_keeps_draft_for_nonterminal_run(tmp_path: Path):
    run = Run(id="x")
    run.add_step(StepKind.think, {"text": "wip"})  # status running
    saver = Autosaver(tmp_path / "a.tine", every_n_steps=1)
    saver.flush(run)
    assert json.loads((tmp_path / "a.tine").read_text())["draft"] is True


# --- Agent crash safety -----------------------------------------------------


class CrashModel:
    name = "crash-model"
    supports_tools = True
    supports_thinking = False

    def __init__(self):
        self._calls = 0

    async def complete(self, messages, tools=None, system=None, temperature=0.0):
        self._calls += 1
        if self._calls == 1:
            return {
                "text": "step1",
                "tool_calls": [{"name": "_noop", "arguments": {}}],
                "cost": 0.0,
            }
        raise RuntimeError("boom")

    async def stream(self, *a, **k) -> AsyncIterator[dict[str, Any]]:
        yield await self.complete(*a, **k)


def _noop() -> str:
    """Do nothing."""
    return "ok"


def test_agent_crash_leaves_resumable_draft(tmp_path: Path):
    target = tmp_path / "r.tine"
    agent = Agent(
        model=CrashModel(),
        tools=[_noop],
        max_steps=10,
        autosave_path=str(target),
        autosave_every_n_steps=1,
    )
    with pytest.raises(RuntimeError, match="boom"):
        agent.run_sync("go")

    assert target.exists()
    result = Run.verify_integrity(target)
    assert result.ok  # the checkpoint is internally consistent
    assert result.draft is True  # the run never completed -> still a draft
    loaded = Run.load(target)
    assert len(loaded.steps) >= 1  # step1 (+ its tool result) survived the crash
