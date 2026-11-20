"""Telemetry shapes that survived the publication rule in a dataset review (Unreleased).

Every fixture is synthetic: made-up ids and values copying only the shapes.
"""

from __future__ import annotations

import json

from opentine import _redact_publish, _redact_telemetry

SID = "00000000-1111-4222-8333-444444444444"
ADAPTER_INIT = {
    "event": "init",
    "session_id": SID,
    "model": "m",
    "tools": ["Bash"],
    "cwd": "/w",
    "apiKeySource": "operator-key-source",
    "slash_commands": ["operator-skill"],
}
ADAPTER_TURN = {
    "event": "assistant",
    "session_id": SID,
    "uuid": "msg-uuid-secret",
    "message": {
        "usage": {"input_tokens": 3, "inference_geo": "geo-secret"},
        "content": [{"type": "tool_use", "input": {"uuid": "agent-data", "session_id": "mine"}}],
    },
}
ADAPTER_LINES = json.dumps(ADAPTER_INIT) + "\n" + json.dumps(ADAPTER_TURN) + "\n"
SECRETS = (SID, "operator-", "msg-uuid-secret", "geo-secret")


def _bytes(value: object) -> tuple[str, int]:
    clean, counts = _redact_publish.scrub_bytes(json.dumps(value).encode(), login=None)
    return clean.decode(), counts["telemetry"]


def _clear(text: str) -> None:
    for secret in SECRETS:
        assert secret not in text, secret


def test_adapter_records_keyed_by_event_lose_their_telemetry():
    clean, removed = _redact_telemetry.scrub(ADAPTER_LINES)
    _clear(clean)
    init, turn = (json.loads(line) for line in clean.splitlines())
    assert init == {"event": "init", "model": "m", "tools": ["Bash"], "cwd": "<CWD>"}
    assert turn["message"]["usage"] == {"input_tokens": 3}
    assert turn["message"]["content"][0]["input"] == {"uuid": "agent-data", "session_id": "mine"}
    assert removed >= 6


def test_adapter_blob_holding_the_capture_is_scrubbed_and_counted():
    clean, removed = _bytes({"stdout": ADAPTER_LINES, "exit_code": 0})
    _clear(clean)
    assert removed >= 6
    assert "agent-data" in json.loads(clean)["stdout"]


def test_otel_gen_ai_prompt_attribute_is_scrubbed():
    span = {
        "name": "chat",
        "attributes": [
            {"key": "gen_ai.prompt", "value": {"stringValue": ADAPTER_LINES}},
            {"key": "session_id", "value": {"stringValue": SID}},
            {"key": "gen_ai.system", "value": {"stringValue": "anthropic"}},
        ],
    }
    clean, removed = _bytes(span)
    _clear(clean)
    attrs = json.loads(clean)["attributes"]
    assert [a["key"] for a in attrs] == ["gen_ai.prompt", "gen_ai.system"]
    assert removed >= 7


def test_inference_geo_goes_from_every_assistant_usage():
    record = {
        "type": "assistant",
        "session_id": "s",
        "message": {"usage": {"output_tokens": 1, "inference_geo": "geo-secret"}},
    }
    clean, removed = _redact_telemetry.scrub(json.dumps(record))
    assert "geo-secret" not in clean and removed == 2
    assert json.loads(clean)["message"]["usage"] == {"output_tokens": 1}


def test_transcript_records_with_camel_session_id_lose_uuids():
    record = {"type": "user", "sessionId": SID, "uuid": "msg-uuid-secret", "message": {}}
    clean, removed = _redact_telemetry.scrub(json.dumps(record))
    _clear(clean)
    assert removed == 2 and json.loads(clean) == {"type": "user", "message": {}}


def test_session_uuid_in_a_projects_path_is_replaced():
    text = f"saved to ~/.claude/projects/-work/{SID}/tool-results/r.txt"
    clean, counts = _redact_publish.scrub_text(text, login=None)
    assert SID not in clean and counts["telemetry"] == 1
    assert clean == "saved to <HOME>/.claude/projects/-work/<SESSION>/tool-results/r.txt"
    escaped = f'"C:\\\\Users\\\\x\\\\.claude\\\\projects\\\\-work\\\\{SID}\\\\tool-results"'
    clean, counts = _redact_publish.scrub_text(escaped, login=None)
    assert SID not in clean and counts["telemetry"] == 1


def test_other_json_is_untouched():
    for value in ({"event": "init", "uuid": "u"}, {"key": "uuid", "value": 1}):
        text = json.dumps(value)
        assert _redact_telemetry.scrub(text) == (text, 0)
