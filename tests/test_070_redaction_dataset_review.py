"""Redaction fixes from the dataset review: tilde homes and harness telemetry (Unreleased)."""

from __future__ import annotations

import json

import pytest

from opentine import _bundle, _redact_publish, _redact_telemetry, _redacted_copy, _redacted_derive
from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.repository import Repo
from opentine.repository.pack import inspect_pack

KEY = b"cd" * 32

# True positives: a real home path.
TILDE_HOMES = [
    ("~/notes.txt", "<HOME>/notes.txt"),
    ("cat ~/x", "cat <HOME>/x"),
    ("~bob/notes.txt", "<HOME>/notes.txt"),
    ('"cwd": "~/proj"', '"cwd": "<HOME>/proj"'),
    ("HOME=~/w", "HOME=<HOME>/w"),
    ("(~/a)", "(<HOME>/a)"),
    ("~\\Documents", "<HOME>\\Documents"),
]
# False positives: a tilde that is content, not a home.
TILDE_CONTENT = [
    "foo#!~bar",
    "expect(parse('foo#!~bar')).toBe(1)",
    "~",
    "a ~ b",
    "x = ~mask",
    "~5 minutes",
    "a~/b",
    "re = /^~user$/",
    "s/~foo/bar/",
    "'~'",
    "name~1",
    "approx ~2x faster",
    "alice@laptop:~$ ls",
    "git log HEAD~3",
    "~bob",
]


@pytest.mark.parametrize(("text", "expected"), TILDE_HOMES)
def test_a_tilde_home_path_is_still_redacted(text, expected):
    assert _redact_publish.scrub_text(text, login=None)[0] == expected


@pytest.mark.parametrize("text", TILDE_CONTENT)
def test_a_tilde_in_ordinary_content_is_left_alone(text):
    clean, counts = _redact_publish.scrub_text(text, login=None)
    assert clean == text and "path" not in counts


def test_the_other_home_forms_still_apply():
    for text in ("/root/x", "/home/u/x", "/Users/u/x", "C:\\Users\\u\\x"):
        assert _redact_publish.scrub_text(text, login=None)[0].startswith("<HOME>")


# A synthetic Claude Code stream-json capture: no real account data.
SID = "00000000-0000-4000-8000-000000000001"
STREAM = [
    {"type": "system", "subtype": "init", "session_id": SID, "cwd": "/tmp/work",
     "model": "claude-test", "tools": ["Bash", "Read"], "permissionMode": "default",
     "mcp_servers": [], "slash_commands": ["x"], "skills": ["s"], "plugins": [{"name": "p"}],
     "apiKeySource": "none", "output_style": "default", "memory_paths": ["/tmp/m"],
     "served_by": "node-1", "inference_geo": "zz", "socket_path": "/tmp/s.sock",
     "capabilities": {"flag": True}, "uuid": "u-1"},
    {"type": "rate_limit_event", "rate_limit_info": {"status": "allowed"}, "uuid": "u-2",
     "session_id": SID},
    {"type": "assistant", "session_id": SID, "uuid": "u-3", "parent_tool_use_id": None,
     "message": {"id": "msg_1", "role": "assistant",
                 "content": [{"type": "text", "text": "done"}]},
     "request_id": "req_0123456789abcdef"},
    {"type": "user", "session_id": SID, "uuid": "u-4",
     "tool_use_result": {"stdout": "ok", "persistedOutputPath": "/tmp/out.txt"},
     "message": {"role": "user", "content": [{"type": "tool_result", "content": "ok"}]}},
    {"type": "result", "subtype": "success", "session_id": SID, "uuid": "u-5",
     "result": "done", "num_turns": 1},
]  # fmt: skip
STREAM_TEXT = "".join(json.dumps(r) + "\n" for r in STREAM)
LEAKS = ("rate_limit", SID, "req_0123", '"uuid"', "persistedOutputPath", "skills", "plugins",
         "served_by", "inference_geo", "memory_paths", "socket_path", "capabilities",
         "slash_commands", "/tmp/work")  # fmt: skip


def test_claude_code_stream_json_loses_its_telemetry():
    clean, removed = _redact_telemetry.scrub(STREAM_TEXT)
    assert removed > 0
    for leak in LEAKS:
        assert leak not in clean, leak
    records = [json.loads(line) for line in clean.splitlines()]
    assert [r["type"] for r in records] == ["system", "assistant", "user", "result"]
    assert records[0] == {"type": "system", "subtype": "init", "cwd": "<CWD>",
                          "model": "claude-test", "tools": ["Bash", "Read"],
                          "permissionMode": "default"}  # fmt: skip
    assert records[1]["message"]["content"][0]["text"] == "done"
    assert records[2]["tool_use_result"] == {"stdout": "ok"}
    assert records[3]["result"] == "done" and records[3]["num_turns"] == 1


def test_telemetry_is_counted_by_the_publication_ruleset():
    clean, counts = _redact_publish.scrub_bytes(STREAM_TEXT.encode(), login=None)
    assert counts["telemetry"] > 0 and SID.encode() not in clean
    whole = json.dumps(STREAM[0], indent=2)
    out, counts = _redact_publish.scrub_text(whole, login=None)
    assert json.loads(out)["cwd"] == "<CWD>" and counts["telemetry"] > 0


NOT_TELEMETRY = [
    '{"type": "system", "uuid": "keep-me"}',  # no session id: not a harness record
    '{"id": "x", "uuid": "u", "session_id": "s"}',  # no harness type
    "plain text with session_id in it",
    "{not json",
    '[{"type": "file", "uuid": "u"}]',
]


@pytest.mark.parametrize("text", NOT_TELEMETRY)
def test_other_json_and_text_is_untouched(text):
    assert _redact_telemetry.scrub(text) == (text, 0)


def test_untouched_lines_keep_their_bytes():
    text = 'header line\n{"type":"result","x":1}\n' + json.dumps(STREAM[1]) + "\r\ntail"
    clean, removed = _redact_telemetry.scrub(text)
    assert removed == 1 and clean == 'header line\n{"type":"result","x":1}\ntail'


def test_the_public_copy_drops_telemetry_and_verifies(tmp_path, monkeypatch):
    monkeypatch.setattr(_redact_publish, "login", lambda: None)
    repo = Repo.init(tmp_path / "s")
    run = Run(id="r", model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": "ran the agent", "stdout": STREAM_TEXT})
    run_id = repo.put_run(run, ref="heads/main").run_id
    counts: dict = {}
    data = _redacted_derive.public_bundle(
        repo, "heads/main", run_id, KEY, algorithm="hmac-sha256", counts=counts
    )
    checked = _bundle.verify(data)
    record = checked.redacted_public
    assert _redacted_copy.check(record, hmac_key=KEY)["state"] == "verified"
    _, objects, _ = inspect_pack(checked.pack)
    for _oid, raw in objects:
        assert SID.encode() not in raw and b"rate_limit_event" not in raw
    assert any("telemetry" in per for per in counts.values())
    target = Repo.init(tmp_path / "pub")
    _bundle.unbundle(target, data, "public")
    assert target.fsck().ok and target.load_run(record["public_run"]) is not None
