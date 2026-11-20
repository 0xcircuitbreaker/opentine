"""Red-team follow-ups to the tilde/telemetry redaction fix (Unreleased)."""

from __future__ import annotations

import json

import pytest

from opentine import _redact_publish, _redact_telemetry

INIT = {
    "type": "system",
    "subtype": "init",
    "session_id": "sid-secret",
    "cwd": "/w",
    "apiKeySource": "operator-key-source",
    "slash_commands": ["operator-skill"],
}


def _scrub(text: str) -> str:
    return _redact_publish.scrub_text(text, login=None)[0]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('"text":"see\\n~/secret/x"', '"text":"see\\n<HOME>/secret/x"'),
        ('"a\\t~/x"', '"a\\t<HOME>/x"'),
        ("echo hi 2>~/log", "echo hi 2><HOME>/log"),
        ("cat <~/in", "cat <<HOME>/in"),
        ("a|~/x", "a|<HOME>/x"),
        ("true&&~/bin/run", "true&&<HOME>/bin/run"),
    ],
)
def test_a_tilde_home_after_an_escape_or_shell_operator_is_redacted(text, expected):
    assert _scrub(text) == expected


@pytest.mark.parametrize("text", ["foo#!~bar", "a~/b", "x.~/y", "re: s/~//"])
def test_tilde_content_stays_content(text):
    assert _scrub(text) == text


def test_a_json_array_of_records_loses_its_telemetry():
    for text in (json.dumps([INIT]), json.dumps([INIT], indent=2)):
        clean, removed = _redact_telemetry.scrub(text)
        assert removed and "sid-secret" not in clean and "operator-" not in clean
        assert json.loads(clean)[0]["cwd"] == "<CWD>"


def test_escaped_stream_inside_a_tool_result_is_scrubbed():
    inner = json.dumps(INIT) + "\n" + json.dumps({"type": "rate_limit_event", "x": 1})
    record = {
        "type": "user",
        "session_id": "outer",
        "message": {"content": [{"type": "tool_result", "content": inner}]},
    }
    clean, removed = _redact_telemetry.scrub(json.dumps(record))
    assert removed >= 3
    assert "sid-secret" not in clean and "operator-" not in clean
    assert "rate_limit_event" not in clean
    json.loads(clean)


def test_a_tool_input_keeps_its_own_keys():
    record = {
        "type": "assistant",
        "session_id": "s",
        "message": {"content": [{"type": "tool_use", "input": {"uuid": "agent-data"}}]},
    }
    clean, removed = _redact_telemetry.scrub(json.dumps(record))
    assert removed == 1 and "agent-data" in clean


def test_gemini_cli_init_is_reduced():
    text = json.dumps({"type": "init", "session_id": "gem-secret", "model": "m", "timestamp": "t"})
    clean, removed = _redact_telemetry.scrub(text)
    assert removed and "gem-secret" not in clean and json.loads(clean)["model"] == "m"


def test_codex_thread_id_is_stripped():
    text = '{"type":"thread.started","thread_id":"0199-secret"}\n{"type":"turn.started"}\n'
    clean, removed = _redact_telemetry.scrub(text)
    assert removed == 1 and "0199-secret" not in clean
    assert clean.endswith('{"type":"turn.started"}\n')
