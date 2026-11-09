"""0.49: the Jules and A2A importers (``tine import --format jules|a2a``)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from opentine import _schemas, cli
from opentine.trace._import_a2a import a2a_events
from opentine.trace._import_jules import jules_events

FIXTURES = Path(__file__).parent / "fixtures"
JULES = FIXTURES / "jules" / "session.json"
A2A = FIXTURES / "a2a" / "task.jsonl"


def test_jules_session_maps_every_documented_activity_and_artifact():
    events = jules_events(JULES.read_bytes())
    kinds = [(e.kind, e.actor) for e in events]
    assert kinds == [("human", "user"), ("model", ""), ("approval", "user"), ("model", ""),
                     ("tool", "bash"), ("human", "user"), ("model", ""),
                     ("tool", "jules.change_set"), ("tool", "jules.media")]  # fmt: skip
    assert {e.trace_id for e in events} == {"1234567890123456789"}
    model = events[1]
    assert (model.model, model.provider, model.usage) == ("jules", "google", {})
    assert [s["title"] for s in model.outputs["steps"]] == ["Reproduce", "Fix"]
    bash = events[4]
    assert bash.outputs["exit_code"] == 1 and bash.parent_span_id == "activity-2"
    patch = events[7].outputs
    assert patch["base_commit"].startswith("0123") and "+SEP = '-'" in patch["patch"]
    assert events[8].outputs == {"mime_type": "image/png", "bytes": 8}  # bytes not imported


def test_jules_accepts_bare_activity_lists_and_jsonl_pages():
    doc = json.loads(JULES.read_text("utf-8"))
    bare = jules_events(json.dumps(doc["activities"]))
    pages = "\n".join(json.dumps({"activities": [a]}) for a in doc["activities"])
    assert len(bare) == len(jules_events(pages)) == 8  # no session prompt
    failed = jules_events(json.dumps([{"sessionFailed": {"reason": "quota"}}]))
    assert failed[0].kind == "error" and failed[0].outputs["reason"] == "quota"


@pytest.mark.parametrize("bad", ["{}", "[]", "not json", '{"activities": []}'])
def test_jules_refuses_what_is_not_a_session(bad):
    with pytest.raises(ValueError, match="Jules"):
        jules_events(bad)


def test_a2a_stream_becomes_one_run_without_duplicate_messages():
    events = a2a_events(A2A.read_bytes())
    kinds = [e.kind for e in events]
    assert kinds == ["human", "model", "approval", "human", "tool", "model"]
    assert {e.trace_id for e in events} == {"ctx-42"}
    assert events[1].provider == "restaurant-agent"
    artifact = events[4].outputs["parts"]
    assert artifact[0]["data"]["party"] == 2
    assert artifact[1] == {"kind": "file", "name": "confirmation.pdf",
                           "mimeType": "application/pdf"}  # fmt: skip


def test_a2a_failed_task_and_bare_message():
    said = {"role": "agent", "messageId": "x", "parts": [{"kind": "text", "text": "no"}]}
    task = {"kind": "task", "id": "t", "contextId": "c",
            "status": {"state": "failed", "message": said}}  # fmt: skip
    events = a2a_events(json.dumps(task))
    assert [e.kind for e in events] == ["model", "error"]
    assert a2a_events(json.dumps({"role": "user", "parts": [{"text": "hi"}]}))[0].kind == "human"
    with pytest.raises(ValueError, match="A2A"):
        a2a_events('{"jsonrpc": "2.0", "id": 1, "result": {}}')


@pytest.mark.parametrize(("fmt", "source", "steps"), [("jules", JULES, 9), ("a2a", A2A, 6)])
def test_cli_imports_each_format(monkeypatch, capsys, tmp_path, fmt, source, steps):
    monkeypatch.chdir(tmp_path)
    out_path = tmp_path / f"{fmt}.tine"
    argv = ["tine", "import", str(source), "--format", fmt, "--save", str(out_path), "--json"]
    monkeypatch.setattr(sys, "argv", argv)
    try:
        cli.main()
    except SystemExit as exc:
        assert not exc.code
    doc = json.loads(capsys.readouterr().out)
    assert doc["format"] == fmt and doc["run"]["step_count"] == steps
    assert _schemas.validate(doc, _schemas.detect(doc))[1] == []
    assert out_path.is_file()


def test_presigned_uris_lose_their_tokens():
    from opentine.trace._import_a2a import a2a_events, bare_uri

    assert bare_uri("https://u:p@b.s3.example/k.png?X-Amz-Signature=abc#f") == (
        "https://b.s3.example/k.png"
    )
    msg = {
        "kind": "message",
        "role": "agent",
        "messageId": "m1",
        "parts": [
            {"kind": "file", "file": {"name": "a.png", "uri": "https://h.example/a?token=SECRET"}}
        ],
    }
    events = a2a_events(json.dumps(msg))
    assert "SECRET" not in json.dumps([e.outputs for e in events], default=str)
