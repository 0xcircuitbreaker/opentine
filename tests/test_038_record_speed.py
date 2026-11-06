"""0.38.0 record speed: prompt-prefix splitting, the redaction LRU, openat touches."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine.kernel import KernelError, ObjectEnvelope, validate_links
from opentine.repository import Repo
from opentine.repository._prompt_parts import join_inputs, split_inputs

SYSTEM = "You are a careful agent. " + "Rule: be precise. " * 40
TOOLS = [{"name": "read_file", "description": "Read a file", "input_schema": {"type": "object"}}]


def _run(n: int = 4, run_id: str = "r1") -> Run:
    run = Run(id=run_id, model_info="mock/m")
    for index in range(n):
        inputs = {"model": "m", "system": SYSTEM, "tools": TOOLS, "messages": [{"i": index}]}
        run.add_step(StepKind.model, inputs, {"text": f"reply {index}"})
    return run


def _events(repo: Repo, run_id: str) -> list[dict]:
    return [repo.get(oid).payload() for oid in repo.get(run_id).payload()["events"]]


def test_new_runs_record_system_and_tools_as_shared_blobs(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    run_id = repo.put_run(_run()).run_id
    events = _events(repo, run_id)
    parts = [event["input_parts"] for event in events]
    assert all(set(item) == {"system", "tools"} for item in parts)
    assert len({item["system"] for item in parts}) == 1  # one blob for every step
    assert len({item["tools"] for item in parts}) == 1
    base = repo.get(events[0]["input_blob"]).body
    assert b"Rule: be precise" not in base and b"read_file" not in base
    # A second run with the same prompt reuses the very same part blobs.
    other = repo.put_run(_run(2, "r2")).run_id
    assert _events(repo, other)[0]["input_parts"] == parts[0]


def test_readers_reconstruct_the_full_request(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    original = _run()
    loaded = repo.load_run(repo.put_run(original, ref="heads/main").run_id)
    assert [step.inputs for step in loaded.steps] == [step.inputs for step in original.steps]


def test_reloaded_run_resaves_to_the_same_ids(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    first = repo.put_run(_run()).run_id
    again = repo.put_run(repo.load_run(first)).run_id
    assert again == first


def test_inputs_without_prompt_fields_are_stored_as_before(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    run = Run(id="plain")
    run.add_step(StepKind.tool, {"name": "x", "system": "", "tools": []}, {"ok": 1})
    event = _events(repo, repo.put_run(run).run_id)[0]
    assert "input_parts" not in event
    assert repo.load_run(repo.put_run(run).run_id).steps[0].inputs == run.steps[0].inputs


def test_parts_are_redacted_like_the_whole_input(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    run = Run(id="secret")
    secret = "sk-" + "a" * 30
    run.add_step(StepKind.model, {"system": f"use key {secret}", "messages": []}, {})
    loaded = repo.load_run(repo.put_run(run).run_id)
    assert secret not in loaded.steps[0].inputs["system"]
    assert "[REDACTED]" in loaded.steps[0].inputs["system"]


def test_kernel_links_parts_so_gc_and_fsck_keep_them():
    blob = "blob:sha256:" + "a" * 64
    event = ObjectEnvelope.create("event", {"input_parts": {"system": blob}})
    assert blob in validate_links(event)
    for bad in ({"system": "event:sha256:" + "b" * 64}, ["x"], "x"):
        with pytest.raises(KernelError):
            validate_links(ObjectEnvelope.create("event", {"input_parts": bad}))


def test_join_refuses_malformed_parts():
    store = {"b1": {"system": "s"}, "b2": {"other": 1}}
    read = store.__getitem__
    assert join_inputs({"m": 1}, {"input_parts": {"system": "b1"}}, read) == {"m": 1, "system": "s"}
    assert join_inputs({"m": 1}, {}, read) == {"m": 1}
    for parts in ({"system": "b2"}, {"bogus": "b1"}, {}, ["b1"]):
        with pytest.raises(ValueError):
            join_inputs({}, {"input_parts": parts}, read)
    with pytest.raises(ValueError):  # a part may not overwrite a base field
        join_inputs({"system": "x"}, {"input_parts": {"system": "b1"}}, read)


def test_split_keeps_non_mapping_inputs_whole():
    written: list = []

    def write(value):
        written.append(value)
        return f"blob{len(written)}"

    assert split_inputs({"a": 1}, write) == ("blob1", None)
    blob, parts = split_inputs({"system": "s", "tools": [1], "a": 1}, write)
    assert parts == {"system": "blob2", "tools": "blob3"} and written[-1] == {"a": 1}


def test_recorder_events_split_and_reload(tmp_path):
    from opentine.trace.recorder import Recorder
    from opentine.trace.schema import TraceEvent

    repo = Repo.init(tmp_path / "repo")
    recorder = Recorder.start(repo, capture=False)
    inputs = {"system": SYSTEM, "tools": TOOLS, "messages": []}
    event_id = recorder.append(TraceEvent("model", 1.0, "t", "s1", inputs=inputs))
    assert set(repo.get(event_id).payload()["input_parts"]) == {"system", "tools"}
    assert repo.load_run(recorder.run_id).steps[0].inputs == inputs


def test_redaction_lru_holds_no_plaintext_and_is_bounded(monkeypatch):
    import opentine._redact_memo as memo
    from opentine.redaction import redact_blob

    memo.LRU.clear()
    secret = b"password=hunter2-the-plaintext"
    assert redact_blob(secret) == b"password=[REDACTED]"
    assert redact_blob(secret) == b"password=[REDACTED]"
    assert all(secret not in key + value for key, value in memo.LRU.items.items())
    monkeypatch.setattr(memo, "LRU_ENTRIES", 4)
    for index in range(20):
        redact_blob(f"plain text value number {index}".encode())
    assert len(memo.LRU.items) <= 4


def test_prefilter_skips_regex_when_no_needle():
    from opentine._redact_edits import sub_step

    class Boom:
        def finditer(self, value):
            raise AssertionError("regex ran")

    step = sub_step(Boom(), b"x", needles=(b"token",))
    assert step(b"nothing to see here") == []


@pytest.mark.skipif(sys.platform == "win32", reason="openat path is POSIX-only")
def test_openat_touch_matches_the_confined_walk(tmp_path):
    from opentine.repository import _link_touch

    repo = Repo.init(tmp_path / "repo")
    oid = repo.put("blob", b"hello")
    assert _link_touch._OPENAT
    path = repo._object_path(oid)
    os.utime(path, (1, 1))
    assert _link_touch.touch_stored(repo.path, oid) is True
    assert os.stat(path).st_mtime > 1
    missing = "blob:sha256:" + "0" * 64
    assert _link_touch.touch_stored(repo.path, missing) is False
    # A symlinked fan-out directory is refused by O_NOFOLLOW: counted as stored
    # (exactly what the confined walk did), and the target outside is untouched.
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / ("1" * 62)
    victim.write_bytes(b"x")
    os.utime(victim, (1, 1))
    fan = Path(repo.path) / "objects" / "blob" / "11"
    fan.symlink_to(outside, target_is_directory=True)
    assert _link_touch.touch_stored(repo.path, "blob:sha256:" + "1" * 64) is True
    assert os.stat(victim).st_mtime == 1
