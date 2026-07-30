"""Round-10 audit regressions: what counts as text (group surrogate).

``json.loads`` accepts an unpaired ``\\udXXX`` escape — what ``JSON.stringify``
emits for a string sliced mid-emoji, so any JS/Java MCP server that truncates a
streamed response is a producer — and hands back a Python str holding a lone
UTF-16 surrogate. UTF-8 has no spelling for one, so the v3 canonical form cannot
carry it, while the ``.tine`` writer used to persist it happily (``json.dumps``
escapes it back to ASCII) and its reader handed it back verbatim. The two formats
therefore disagreed about what a valid run was: an archive that saved, loaded and
verified could not enter a v3 repository, and ``tine migrate-v3`` refused it with
a bare codec message.

These tests pin one rule for both formats: a string that UTF-8 cannot encode is
refused at ``.tine`` write *and* at ``.tine`` read, with the offending field path
named, and a real surrogate *pair* — an ordinary emoji — keeps working end to end.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest
from rich.console import Console

from opentine import Run, RunStatus, StepKind
from opentine._artifact_io import parse_artifact_json
from opentine._unicode_text import assert_unicode_text, lone_surrogate_path, surrogate_suspect
from opentine.index import RunIndex
from opentine.repo_cli import cmd_repo
from opentine.repository import Repo
from opentine.trace.recorder import Recorder

# Exactly what a JS-side JSON.stringify emits for a string sliced mid-emoji.
LONE_HIGH = json.loads('{"p": "done \\ud83d"}')["p"]
LONE_LOW = json.loads('{"p": "done \\udc00"}')["p"]
PAIR = json.loads('{"p": "done \\ud83d\\ude00"}')["p"]


def _run(text: str, run_id: str = "r") -> Run:
    run = Run(id=run_id, model_info="m", user_prompt=text)
    run.add_step(StepKind.tool, {"text": text, "name": "t"}, {"result": text})
    run.status = RunStatus.completed
    return run


def _poison(tmp_path: Path, field: str = "user_prompt") -> Path:
    """A .tine archive an older build could write, produced without the writer."""
    healthy = _run("done", "legacy").save(tmp_path / "legacy.tine")
    data = json.loads(healthy.read_text())
    data["metadata"][field] = LONE_HIGH
    poisoned = tmp_path / "poisoned.tine"
    poisoned.write_text(json.dumps(data, indent=2, sort_keys=True))
    return poisoned


# --- the escape json.loads accepts is not a Unicode scalar value -------------


def test_json_loads_really_does_hand_back_a_lone_surrogate():
    # The premise: the producer is a conforming JSON encoder, not a bug in ours.
    assert LONE_HIGH == "done \ud83d" and len(LONE_HIGH) == 6
    with pytest.raises(UnicodeEncodeError):
        LONE_HIGH.encode("utf-8")
    # A *pair* of escapes is one scalar value: json.loads recombines it, so real
    # emoji must keep working. Rejecting the pair would be the worse bug.
    assert PAIR == "done \U0001f600" and len(PAIR) == 6
    assert PAIR.encode("utf-8")


# --- writers refuse it, naming the field path, while the run is in memory ----


def test_save_refuses_a_lone_high_surrogate_and_names_the_field(tmp_path):
    target = tmp_path / "run.tine"
    with pytest.raises(ValueError, match=r"unpaired UTF-16 surrogate at metadata\.user_prompt"):
        _run(LONE_HIGH).save(target)
    assert not target.exists()  # nothing half-written to migrate later


def test_save_refuses_a_lone_low_surrogate_inside_a_step(tmp_path):
    run = Run(id="stepwise", model_info="m", user_prompt="fine")
    run.add_step(StepKind.tool, {"text": LONE_LOW}, {"result": "ok"})
    with pytest.raises(ValueError) as info:
        run.save(tmp_path / "run.tine")
    message = str(info.value)
    assert "unpaired UTF-16 surrogate at graph.steps." in message
    assert message.endswith("on your behalf")
    assert ".inputs.text" in message
    assert "will not substitute a replacement character" in message


def test_save_refuses_a_lone_surrogate_in_a_tag_and_in_a_step_output(tmp_path):
    tagged = _run("fine", "tagged")
    tagged.tags = [LONE_HIGH]
    with pytest.raises(ValueError, match=r"surrogate at metadata\.tags\[0\]"):
        tagged.save(tmp_path / "tagged.tine")
    out = Run(id="outy", model_info="m", user_prompt="fine")
    out.add_step(StepKind.tool, {"text": "fine"}, {"result": LONE_HIGH})
    with pytest.raises(ValueError, match=r"surrogate at graph\.steps\..*\.outputs\.result"):
        out.save(tmp_path / "outy.tine")


def test_a_surrogate_pair_still_saves_loads_verifies_and_migrates(tmp_path):
    target = _run(PAIR, "emoji").save(tmp_path / "emoji.tine")
    loaded = Run.load(target)
    assert loaded.user_prompt == PAIR
    assert loaded.steps[0].outputs["result"] == PAIR
    assert Run.verify_integrity(target).ok
    repo = Repo.init(tmp_path / "repo")
    assert repo.migrate_v2(target, ref="heads/main").run_id.startswith("run:sha256:")
    assert repo.put_run(_run(PAIR, "emoji2"), ref="heads/two").run_id
    assert repo.fsck().ok


# --- readers refuse the archives older builds already wrote ------------------


def test_load_refuses_a_pre_existing_poisoned_archive_with_the_path(tmp_path):
    poisoned = _poison(tmp_path)
    with pytest.raises(ValueError, match=r"\.tine artifact holds an unpaired UTF-16 surrogate"):
        Run.load(poisoned)
    # Typed refusal, not a codec error: the bytes stay on disk and are repairable
    # because the offending escape is ASCII in the file.
    assert "\\ud83d" in poisoned.read_text()


def test_verify_integrity_no_longer_calls_an_unmigratable_archive_healthy(tmp_path):
    result = Run.verify_integrity(_poison(tmp_path))
    assert not result.ok
    assert "unpaired UTF-16 surrogate" in (result.reason or "")


def test_migrate_v2_refuses_with_an_explanation_and_writes_nothing(tmp_path):
    poisoned = _poison(tmp_path)
    repo = Repo.init(tmp_path / "repo")
    with pytest.raises(ValueError) as info:
        repo.migrate_v2(poisoned, ref="heads/main")
    assert "unpaired UTF-16 surrogate at metadata.user_prompt" in str(info.value)
    assert "codec can't encode" not in str(info.value)
    check = repo.fsck()
    assert check.ok and check.objects == 0 and check.refs == 0
    assert repo.read_ref("heads/main") is None


def test_migrate_v3_cli_exits_one_with_the_actionable_message(tmp_path, monkeypatch, capsys):
    poisoned = _poison(tmp_path)
    repo_dir = tmp_path / "repo"
    Repo.init(repo_dir)
    monkeypatch.chdir(repo_dir)
    args = argparse.Namespace(
        command="migrate-v3",
        source=str(poisoned),
        ref="heads/main",
        allow_unverified=False,
        repo=".",
    )
    with pytest.raises(SystemExit) as exit_info:
        cmd_repo(args, Console())
    assert exit_info.value.code == 1
    assert "unpaired UTF-16 surrogate" in capsys.readouterr().err


def test_one_poisoned_archive_no_longer_blinds_the_whole_index(tmp_path):
    # _searchable_text feeds run.user_prompt through redact_value, whose
    # value.encode("utf-8") raised outside _build_entry's containment: a single
    # poisoned file made `tine ls`/`tine search` fail for every run in the
    # directory. Refusing at read puts the failure back inside the containment.
    runs = tmp_path / ".tine_runs"
    runs.mkdir()
    _run("hello", "ordinary").save(runs / "ordinary.tine")
    _run(PAIR, "emoji").save(runs / "emoji.tine")
    data = json.loads((runs / "ordinary.tine").read_text())
    data["metadata"]["user_prompt"] = LONE_HIGH
    (runs / "poisoned.tine").write_text(json.dumps(data, indent=2, sort_keys=True))

    index = RunIndex.open(runs).sync()
    assert set(index.entries) == {"ordinary.tine", "emoji.tine", "poisoned.tine"}
    assert index.entries["poisoned.tine"].unreadable
    healthy = {name for name, entry in index.entries.items() if not entry.unreadable}
    assert healthy == {"ordinary.tine", "emoji.tine"}
    assert [entry.run_id for entry in index.search("hello")] == ["ordinary"]


# --- the in-memory routes into v3 stay fail-closed --------------------------


def test_put_run_and_recorder_refuse_a_lone_surrogate_without_writing_a_ref(tmp_path):
    # These reach the v3 canonical form without passing through .tine at all
    # (repository/runs.py prompt blobs, redact_value under guarded_blob_body,
    # trace/recorder.py). UnicodeEncodeError is a ValueError subclass, so this
    # holds both today and once those refusals are given typed messages.
    repo = Repo.init(tmp_path / "repo")
    with pytest.raises(ValueError):
        repo.put_run(_run(LONE_HIGH, "direct"), ref="heads/main")
    assert repo.read_ref("heads/main") is None

    recorded = Repo.init(tmp_path / "rec")
    with pytest.raises(ValueError):
        Recorder.start(recorded, prompt=LONE_LOW, system="s", ref="heads/main")
    assert recorded.read_ref("heads/main") is None
    # The same recorder call with a real emoji is unaffected.
    assert Recorder.start(Repo.init(tmp_path / "rec2"), prompt=PAIR, system="s").run_id


# --- the guard itself: paths, no false positives, no recursion --------------


def test_lone_surrogate_path_reports_keys_indexes_and_nothing_when_clean():
    assert lone_surrogate_path({"a": {"b": ["ok", LONE_HIGH]}}) == "a.b[1]"
    assert lone_surrogate_path({LONE_LOW: "value"}) == f"{LONE_LOW} (object key)"
    assert lone_surrogate_path(LONE_HIGH) == "<root>"
    assert lone_surrogate_path({"a": [1, 2.5, None, True, PAIR, ("t",)]}) is None
    assert lone_surrogate_path({"emoji": PAIR, "nested": {"deep": ["fine"]}}) is None


def test_the_refusal_message_is_itself_encodable_text(tmp_path):
    # A guard against un-encodable text must not emit un-encodable text. The path
    # carries the offending code unit when the surrogate is an object *key*, so
    # str(exc).encode() raised the very UnicodeEncodeError this rule removes, and
    # _terminal's sanitizer rendered the key as "?" — losing the one detail that
    # made the refusal actionable. Both writer and reader are pinned.
    keyed = Run(id="keyed", model_info="m", user_prompt="fine")
    keyed.add_step(StepKind.tool, {"text": "t", LONE_HIGH: "v"}, {"result": "ok"})
    with pytest.raises(ValueError) as writer_info:
        keyed.save(tmp_path / "keyed.tine")

    body = json.dumps({"format_version": 2, "d": {LONE_LOW: 1}})
    with pytest.raises(ValueError) as reader_info:
        parse_artifact_json(body)

    for info in (writer_info, reader_info):
        message = str(info.value)
        assert message.encode("utf-8")  # would raise UnicodeEncodeError before
        assert "(object key)" in message
        assert "\\ud" in message.lower()  # the code unit is named, not replaced
    # A legal non-ASCII key is still shown verbatim, not escaped away.
    with pytest.raises(ValueError, match=r"héllo\.deep"):
        assert_unicode_text({"héllo": {"deep": LONE_HIGH}}, where="run")


def test_literal_backslash_u_text_is_data_not_a_surrogate(tmp_path):
    # A step output *describing* an escape ("\\ud83d") trips the byte-level
    # prefilter; only the decoded value decides, so this must still save.
    literal = _run("escape sample: \\ud83d and \\uDC00", "literal")
    target = literal.save(tmp_path / "literal.tine")
    assert Run.load(target).user_prompt == "escape sample: \\ud83d and \\uDC00"
    assert surrogate_suspect(target.read_text()) and surrogate_suspect(target.read_bytes())
    assert lone_surrogate_path(json.loads(target.read_text())) is None


def test_guard_walks_maximum_legal_nesting_without_recursion_error():
    depth = 400  # under validate_json_shape's 512, well over recursion comfort
    payload: object = LONE_HIGH
    for index in range(depth):
        payload = {"k": [payload]} if index % 2 else [{"k": payload}]
    path = lone_surrogate_path(payload)
    assert path is not None and path.count("k") == depth
    with pytest.raises(ValueError, match="unpaired UTF-16 surrogate"):
        assert_unicode_text(payload, where="deep value")


def test_reader_accepts_escaped_pairs_and_refuses_split_ones():
    body = '{"format_version": 2, "text": "\\ud83d\\ude00"}'
    assert parse_artifact_json(body)["text"] == "\U0001f600"
    assert parse_artifact_json(body.encode())["text"] == "\U0001f600"
    for broken in ('{"t": "\\ud83d\\ud83d"}', '{"t": "\\udc00\\ud83d"}', '{"\\udfff": 1}'):
        with pytest.raises(ValueError, match="unpaired UTF-16 surrogate"):
            parse_artifact_json(broken)
        with pytest.raises(ValueError, match="unpaired UTF-16 surrogate"):
            parse_artifact_json(broken.encode())


def test_raw_cesu8_surrogate_bytes_are_refused_like_the_escape(tmp_path):
    # json.loads decodes a *bytes* argument with errors="surrogatepass", so raw
    # CESU-8/WTF-8 surrogate bytes (a Java or utf8mb3 producer) decode to a lone
    # surrogate without ever appearing as an escape. A prefilter that only looked
    # for "\\ud" missed this second producer entirely.
    for encoded in (b'{"t": "a\xed\xa0\xbd"}', b'{"t": "\xed\xbf\xbf"}'):
        with pytest.raises(ValueError, match="unpaired UTF-16 surrogate"):
            parse_artifact_json(encoded)
    # A CESU-8 *pair* is still two surrogate code units after decoding: refused,
    # because reinterpreting those bytes as one emoji would be a silent rewrite.
    with pytest.raises(ValueError, match="unpaired UTF-16 surrogate"):
        parse_artifact_json(b'{"t": "\xed\xa0\xbd\xed\xb8\x80"}')
    # U+D7FF (ED 9F BF) is ordinary text one byte below the surrogate block.
    assert parse_artifact_json(b'{"t": "\xed\x9f\xbf ok"}')["t"] == "퟿ ok"
    # Real UTF-8 astral bytes are untouched.
    assert parse_artifact_json('{"t": "\U0001f600"}'.encode())["t"] == "\U0001f600"

    poisoned = tmp_path / "cesu8.tine"
    healthy = _run("done", "cesu").save(tmp_path / "healthy.tine")
    poisoned.write_bytes(healthy.read_bytes().replace(b'"done"', b'"\xed\xa0\xbd"'))
    with pytest.raises(ValueError, match="unpaired UTF-16 surrogate"):
        Run.load(poisoned)


def test_clean_artifacts_skip_the_walk_entirely(tmp_path):
    target = _run("no escapes here", "clean").save(tmp_path / "clean.tine")
    assert not surrogate_suspect(target.read_bytes())
    assert not surrogate_suspect(target.read_text())
    assert Run.load(target).user_prompt == "no escapes here"
