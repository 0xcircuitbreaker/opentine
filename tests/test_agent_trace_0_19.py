"""0.19: ``tine export --format agent-trace`` (Agent Trace RFC 0.1.0)."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime
from pathlib import Path

import pytest

from opentine import cli
from opentine._agent_trace import find_root, model_id, to_agent_trace
from opentine.graph import Run, StepKind

FIXTURES = Path(__file__).parent / "fixtures" / "agent_trace"
SCHEMA = FIXTURES / "trace-record.schema.json"
SCHEMA_SHA256 = "f86ded10e845445a21093283092752192b6c614093168035da93a47f696ca5eb"


def _validate(value, schema, root, where="$"):
    """The JSON Schema subset the vendored Agent Trace schema uses."""
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        return _validate(value, root["definitions"][name], root, where)
    kind = schema.get("type")
    checks = {"object": dict, "array": list, "string": str}
    if kind == "integer":
        assert isinstance(value, int) and not isinstance(value, bool), where
    elif kind:
        assert isinstance(value, checks[kind]), f"{where}: not {kind}"
    if "enum" in schema:
        assert value in schema["enum"], where
    if "minimum" in schema:
        assert value >= schema["minimum"], where
    if "maxLength" in schema:
        assert len(value) <= schema["maxLength"], where
    if "pattern" in schema:
        assert re.search(schema["pattern"], value), where
    if schema.get("format") == "uuid":
        uuid.UUID(value)
    if schema.get("format") == "date-time":
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    if kind == "object":
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            assert key in value, f"{where}: missing {key}"
        for key, item in value.items():
            if key in props:
                _validate(item, props[key], root, f"{where}.{key}")
            else:
                assert schema.get("additionalProperties", True) is not False, f"{where}.{key}"
    if kind == "array" and "items" in schema:
        for index, item in enumerate(value):
            _validate(item, schema["items"], root, f"{where}[{index}]")


def _valid(record):
    root = json.loads(SCHEMA.read_text())
    _validate(record, root, root)


def _run(root: Path) -> Run:
    run = Run(id="run-at-1", model_info="claude-opus-5-5")
    run.add_step(
        StepKind.tool,
        {
            "name": "Write",
            "arguments": {"file_path": str(root / "src/a.py"), "content": "a\nb\nc\n"},
        },
        provider="anthropic",
    )
    run.add_step(
        StepKind.tool,
        {"name": "Edit", "arguments": {"file_path": "src/b.py", "new_string": "x"}},
    )
    run.add_step(
        StepKind.tool,
        {"name": "Write", "arguments": {"file_path": "/elsewhere/c.py", "content": "z"}},
    )
    return run


def test_vendored_schema_is_the_published_one():
    assert hashlib.sha256(SCHEMA.read_bytes()).hexdigest() == SCHEMA_SHA256


def test_record_is_schema_valid_with_ranges_only_where_known(tmp_path):
    run = _run(tmp_path)
    record = to_agent_trace(run, tmp_path)
    _valid(record)
    assert record["version"] == "0.1"
    assert record["tool"]["name"] == "opentine"
    files = {item["path"]: item["conversations"] for item in record["files"]}
    assert set(files) == {"src/a.py", "src/b.py"}  # /elsewhere is outside the root
    (a,) = files["src/a.py"]
    assert a["contributor"] == {"type": "ai", "model_id": "anthropic/claude-opus-5-5"}
    assert a["ranges"] == [{"start_line": 1, "end_line": 3}]
    (b,) = files["src/b.py"]
    assert b["ranges"] == [] and b["contributor"]["model_id"] == "claude-opus-5-5"
    meta = record["metadata"]["io.github.0xcircuitbreaker.opentine"]
    assert meta["run_id"] == "run-at-1" and meta["paths_outside_root"] == 1
    assert record == to_agent_trace(run, tmp_path)  # deterministic


def test_overwritten_full_write_loses_its_range(tmp_path):
    run = _run(tmp_path)
    run.add_step(
        StepKind.tool,
        {"name": "Edit", "arguments": {"file_path": "src/a.py", "new_string": "q"}},
    )
    record = to_agent_trace(run, tmp_path)
    _valid(record)
    convs = next(f["conversations"] for f in record["files"] if f["path"] == "src/a.py")
    assert len(convs) == 2 and all(c["ranges"] == [] for c in convs)


def test_failed_writes_and_empty_runs(tmp_path):
    run = Run(id="empty")
    run.add_step(
        StepKind.tool,
        {"name": "Write", "arguments": {"file_path": "x.py", "content": "1"}},
        {"is_error": True},
    )
    record = to_agent_trace(run, tmp_path)
    _valid(record)
    assert record["files"] == []


def test_model_id_and_root():
    assert model_id("gpt-6", "openai") == "openai/gpt-6"
    assert model_id("openai/gpt-6", "openai") == "openai/gpt-6"
    assert model_id("m" * 300, "") == "m" * 250
    assert find_root(Path("/")) == Path("/").resolve()


def test_cli_export_writes_a_valid_record(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".git").mkdir()
    saved = tmp_path / "run.tine"
    _run(tmp_path).save(saved)
    out = tmp_path / "trace.json"
    cli.main(["export", str(saved), "--format", "agent-trace", "--output", str(out)])
    record = json.loads(out.read_text())
    _valid(record)
    assert [f["path"] for f in record["files"]] == ["src/a.py", "src/b.py"]
    with pytest.raises(SystemExit):
        cli.main(
            ["export", str(saved), "--format", "agent-trace", "--endpoint", "https://x.invalid"]
        )
