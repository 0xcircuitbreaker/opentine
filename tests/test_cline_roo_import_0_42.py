"""0.42: ``tine import`` reads Cline and Roo Code task histories.

Fixtures under ``tests/fixtures/cline/`` and ``tests/fixtures/roo/`` follow the
globalStorage task layout described in ``tests/fixtures/cline/SOURCE.txt``.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from opentine import _cli_import_sessions as sessions
from opentine import cli
from opentine._cli_import_read import detect_and_read
from opentine.core import Run
from opentine.trace._transcript_cline import cline_events, usage_of

FIXTURES = Path(__file__).parent / "fixtures"
CLINE = FIXTURES / "cline" / "1730985600000"
ROO = (
    FIXTURES
    / "roo"
    / "rooveterinaryinc.roo-cline"
    / "tasks"
    / "0b5e2f4c-6a1d-4c39-9f0e-2d7a8b1c3e44"
)


def test_cline_task_maps_turns_tools_and_usage():
    events = cline_events(CLINE)
    assert [e.kind for e in events] == ["human", "model", "tool", "model", "tool", "human"]
    first, model, xml_tool, native_model, native_tool, feedback = events
    assert "Add a --verbose flag" in first.inputs["text"]
    assert "environment_details" not in first.inputs["text"]
    assert first.attributes["environment_details_dropped"] == 2
    assert model.model == "claude-sonnet-4-5-20250929" and model.provider == "anthropic"
    assert model.usage == {"input": 2400, "output": 60, "cache_write_5m": 2100}
    assert model.attributes["reported_cost_usd"] == 0.0089
    assert model.timestamp == pytest.approx(1730985600.2)
    assert xml_tool.actor == "read_file" and "argparse" in xml_tool.outputs["result"]
    # api_req_started wins over the message's own metrics block.
    assert native_model.usage == {
        "input": 15,
        "output": 90,
        "cache_read": 2100,
        "cache_write_5m": 120,
    }
    assert native_tool.actor == "replace_in_file"
    assert native_tool.inputs["tool_use_id"] == "toolu_cline_1"
    assert "short alias" in feedback.inputs["text"]


def test_roo_task_reads_openai_protocol_and_skips_reasoning_items():
    events = cline_events(ROO, "roo-task")
    assert [e.kind for e in events] == ["human", "model", "tool", "model"]
    # tokensIn includes cache reads under apiProtocol "openai".
    assert events[1].usage == {"input": 904, "output": 120, "cache_read": 4096}
    assert events[2].actor == "execute_command" and "KeyError" in events[2].outputs["result"]
    assert all(e.attributes["source"] == "roo-task" for e in events)


def test_usage_falls_back_to_message_metrics():
    metrics = {"tokens": {"prompt": 100, "completion": 7, "cached": 40}}
    assert usage_of({}, metrics) == {"input": 60, "output": 7, "cache_read": 40}
    assert usage_of({"tokensIn": 3}, metrics) == {"input": 3}


def test_auto_detects_directory_and_history_file():
    assert detect_and_read(str(CLINE), "auto")[0] == "cline-task"
    fmt, events = detect_and_read(str(ROO / "api_conversation_history.json"), "auto")
    assert fmt == "roo-task" and len(events) == 4


def test_cli_import_records_the_capture_marker(tmp_path, capsys):
    out = tmp_path / "run.tine"
    cli.main(["import", str(CLINE), "--save", str(out), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["format"] == "cline-task"
    run = Run.load(out)
    assert run.metadata["capture"]["source_format"] == "cline-task"


def test_malformed_history_is_refused(tmp_path):
    task = tmp_path / "123"
    task.mkdir()
    (task / "api_conversation_history.json").write_text('{"role": "user"}')
    with pytest.raises(ValueError, match="JSON list"):
        cline_events(task)
    (task / "api_conversation_history.json").write_text("[nope")
    with pytest.raises(ValueError, match="not valid JSON"):
        cline_events(task)
    with pytest.raises(ValueError, match="no api_conversation_history"):
        cline_events(tmp_path)


def test_default_location_lists_globalstorage_tasks(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(sessions.sys, "platform", "linux")
    storage = tmp_path / "cfg" / "Code" / "User" / "globalStorage"
    shutil.copytree(CLINE, storage / "saoudrizwan.claude-dev" / "tasks" / CLINE.name)
    shutil.copytree(ROO, storage / "rooveterinaryinc.roo-cline" / "tasks" / ROO.name)
    found = {item.source_format for item in sessions.sessions(None)}
    assert {"cline-task", "roo-task"} <= found
    assert sessions.resolve("0b5e2f4c", "roo-task").path.parent.name == ROO.name


def test_every_owned_fixture_exists_and_has_an_owner():
    rows = [
        line.split()
        for line in (FIXTURES / "OWNERS").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert rows and all(len(row) == 2 for row in rows)
    assert all((FIXTURES / path).exists() for path, _ in rows)
