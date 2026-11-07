"""0.42: ``tine import --format har`` turns the LLM calls of a HAR 1.2 archive into a run."""

from __future__ import annotations

import base64
import json

import pytest

from opentine import Run
from opentine.cli import main
from opentine.trace._import_har import har_events, upstream_for

SECRET = "sk-test-SECRETVALUE0123456789abcdef"


def _entry(url, request, response, *, started, mime="application/json", status=200, b64=False):
    text = response if isinstance(response, str) else json.dumps(response)
    content = {"mimeType": mime, "size": len(text), "text": text}
    if b64:
        content.update(text=base64.b64encode(text.encode()).decode(), encoding="base64")
    return {
        "startedDateTime": started,
        "time": 1500,
        "request": {
            "method": "POST",
            "url": url,
            "headers": [{"name": "Authorization", "value": "Bearer " + SECRET}],
            "postData": {"mimeType": "application/json", "text": json.dumps(request)},
        },
        "response": {"status": status, "headers": [], "content": content},
    }


def _har():
    sse = "".join(
        f"data: {json.dumps(e)}\n\n"
        for e in (
            {
                "type": "message_start",
                "message": {"model": "claude-x", "usage": {"input_tokens": 9}},
            },
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "yo"}},
            {"type": "message_delta", "usage": {"output_tokens": 4}},
        )
    )
    entries = [
        _entry(
            "https://api.anthropic.com/v1/messages",
            {"model": "claude-x", "stream": True},
            sse,
            started="2026-11-01T10:00:02.000Z",
            mime="text/event-stream",
        ),
        _entry(
            "https://api.openai.com/v1/chat/completions",
            {"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]},
            {
                "model": "gpt-x",
                "choices": [{"message": {"content": "hello"}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3},
            },
            started="2026-11-01T10:00:00.000Z",
            b64=True,
        ),
        _entry(
            f"https://generativelanguage.googleapis.com/v1beta/models/g-1:generateContent?key={SECRET}",
            {"contents": []},
            {"error": {"message": "quota"}},
            started="2026-11-01T10:00:03.000Z",
            status=429,
        ),
        _entry("https://example.com/index.html", {}, "<html>", started="2026-11-01T10:00:01Z"),
    ]
    return {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}


def test_har_entries_become_model_events_in_start_order():
    events = har_events(json.dumps(_har()))
    assert [e.provider for e in events] == ["openai", "anthropic", "google"]
    assert [e.model for e in events] == ["gpt-x", "claude-x", "g-1"]
    assert events[0].outputs["text"] == "hello" and events[1].outputs["text"] == "yo"
    assert events[0].usage["input"] == 7 and events[1].usage["output"] == 4
    assert events[0].duration == 1.5
    assert events[2].outputs["error"]["type"] == "HTTPError"
    assert all(SECRET not in json.dumps(e.to_dict()) for e in events)


def test_cli_import_har(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "calls.har").write_text(json.dumps(_har()), encoding="utf-8")
    main(["import", "calls.har", "--format", "har", "--save", "out.tine"])
    run = Run.load(tmp_path / "out.tine")
    assert len(run.graph.steps) == 3
    assert SECRET not in (tmp_path / "out.tine").read_bytes().decode("utf-8", "replace")


@pytest.mark.parametrize(
    ("url", "name"),
    [
        ("https://r1.openai.azure.com/openai/deployments/d/chat/completions", "azure"),
        ("http://localhost:4000/v1/chat/completions", "openai"),
        ("http://gw/v1/messages", "anthropic"),
        ("https://api.x.ai/v1/chat/completions", "xai"),
        ("https://example.com/", None),
    ],
)
def test_upstream_recognition(url, name):
    assert upstream_for(url) == name


@pytest.mark.parametrize("data", [b"not json", b"{}", b'{"log": {"entries": []}}', b"[1]"])
def test_non_har_or_empty_is_refused(data):
    with pytest.raises(ValueError):
        har_events(data)
