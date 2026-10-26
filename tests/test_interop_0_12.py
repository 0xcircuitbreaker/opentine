"""0.12 interop: ATIF import/export, OpenCode's SQLite store, agent-CLI hooks, subagent edges.

Fixture sources:

* ATIF -- harbor-framework/harbor ``rfcs/0001-trajectory-format.md`` (v1.8): the
  root/step/metrics field names, ``prompt_tokens`` including ``cached_tokens``,
  ``completion_tokens`` including reasoning, embedded ``subagent_trajectories``
  referenced by ``observation.results[].subagent_trajectory_ref[].trajectory_id``.
* OpenCode -- anomalyco/opencode (branch ``dev``): ``session``/``message``/``part``
  tables (drizzle migrations), assistant ``message.data`` ``tokens{input, output,
  reasoning, cache{read, write}}`` filled as exclusive buckets by
  ``packages/core/src/session/usage.ts``, ``part.data`` ``type: "tool"`` with
  ``callID``/``state``, and child sessions linked by ``session.parent_id``.
* Hooks -- Claude Code hooks docs, Codex ``learn.chatgpt.com/docs/hooks`` (``hooks.json``,
  ``SessionEnd`` timeout in seconds, max 3), Gemini CLI ``docs/hooks/index.md``.
"""

from __future__ import annotations

import argparse
import json
import sqlite3

import pytest

from opentine._atif import atif_events
from opentine._atif_export import to_atif
from opentine._atif_parse import model_provider
from opentine._cli_hook_agents import AGENTS, MARKER, read_config, with_ours, without_ours
from opentine._cli_import_read import detect_and_read
from opentine.trace._transcript_opencode import opencode_events


def _atif(**extra):
    child = {
        "schema_version": "ATIF-v1.8",
        "session_id": "s-child",
        "trajectory_id": "t-child",
        "agent": {"name": "researcher", "version": "1", "model_name": "claude-haiku-4-5"},
        "steps": [
            {"step_id": 1, "source": "user", "message": "look it up"},
            {"step_id": 2, "source": "agent", "message": "found",
             "metrics": {"prompt_tokens": 50, "completion_tokens": 5, "cost_usd": 99.0}},
        ],
    }  # fmt: skip
    document = {
        "schema_version": "ATIF-v1.8",
        "session_id": "s-root",
        "trajectory_id": "t-root",
        "agent": {"name": "harbor", "version": "1", "model_name": "anthropic/claude-sonnet-4-5"},
        "steps": [
            {"step_id": 1, "timestamp": "2026-01-01T00:00:00Z", "source": "user",
             "message": "hi"},
            {"step_id": 2, "timestamp": "2026-01-01T00:00:01Z", "source": "agent",
             "message": "delegating", "reasoning_content": "think",
             "tool_calls": [{"tool_call_id": "c1", "function_name": "Task",
                             "arguments": {"q": "x"}}],
             "observation": {"results": [{"source_call_id": "c1", "content": "done",
                                          "subagent_trajectory_ref": [
                                              {"trajectory_id": "t-child"},
                                              {"trajectory_path": "/etc/passwd"}]}]},
             "metrics": {"prompt_tokens": 1000, "completion_tokens": 300, "cached_tokens": 600,
                         "cost_usd": 12.5,
                         "extra": {"reasoning_tokens": 100,
                                   "cache_creation_input_tokens": 200}}},
        ],
        "subagent_trajectories": [child],
    }  # fmt: skip
    document.update(extra)
    return document


def _write(tmp_path, document, name="trajectory.json"):
    path = tmp_path / name
    path.write_text(json.dumps(document))
    return path


def test_atif_usage_is_split_into_exclusive_buckets_and_file_cost_is_not_trusted(tmp_path):
    events = atif_events(_write(tmp_path, _atif()))
    model = next(e for e in events if e.kind == "model" and not e.span_id.startswith("sub-"))
    assert model.usage == {
        "input": 200, "cache_read": 600, "cache_write_5m": 200, "output": 200, "reasoning": 100,
    }  # fmt: skip
    assert model.model == "claude-sonnet-4-5" and model.provider == "anthropic"
    assert model.cost is None
    assert model.attributes["atif.cost_usd"] == 12.5


def test_atif_embedded_subagent_is_a_typed_edge_under_its_tool_call(tmp_path):
    events = atif_events(_write(tmp_path, _atif()))
    by_id = {e.span_id: e for e in events}
    edge = next(e for e in events if e.kind == "subagent")
    assert by_id[edge.parent_span_id].kind == "tool"
    child = [e for e in events if e.span_id.startswith(edge.span_id + "/")]
    assert [e.kind for e in child] == ["human", "model"]
    assert child[0].parent_span_id == edge.span_id
    assert child[1].provider == "anthropic" and child[1].cost is None
    assert len({e.trace_id for e in events}) == 1 and len(by_id) == len(events)
    # The file-path reference is reported, never opened.
    assert any("not followed" in w for w in events[0].attributes["opentine.import_warnings"])


def test_atif_is_auto_detected_and_bad_shapes_are_refused(tmp_path):
    fmt, events = detect_and_read(str(_write(tmp_path, _atif())), "auto")
    assert fmt == "atif" and events
    with pytest.raises(ValueError):
        atif_events(_write(tmp_path, {"schema_version": "v1", "steps": []}, "x.json"))


def test_atif_copied_context_is_not_billed_twice(tmp_path):
    document = _atif()
    document["steps"][1]["is_copied_context"] = True
    model = next(e for e in atif_events(_write(tmp_path, document)) if e.kind == "model")
    assert model.usage == {} and model.attributes["atif.is_copied_context"] is True


def test_atif_subagent_cycles_and_depth_are_bounded(tmp_path):
    document = _atif()
    child = document["subagent_trajectories"][0]
    child["steps"].append(
        {"step_id": 3, "source": "agent", "message": "loop",
         "observation": {"results": [{"subagent_trajectory_ref": [{"trajectory_id": "t-child"}]}]}}
    )  # fmt: skip
    events = atif_events(_write(tmp_path, document))
    assert sum(e.kind == "subagent" for e in events) == 1


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("openai/gpt-5", ("gpt-5", "openai")), ("gemini-2.5-pro", ("gemini-2.5-pro", "google")),
     ("meta-llama/Llama-3-70b", ("meta-llama/Llama-3-70b", "")), ("", ("", ""))],
)  # fmt: skip
def test_atif_model_provider_inference(raw, expected):
    assert model_provider(raw) == expected


def _run(steps):
    from opentine._graph_types import Step, StepKind

    class _R:
        id = "run-1"
        model_info = "claude-sonnet-4-5"
        metadata: dict = {}
        status = "done"

    run = _R()
    run.steps = steps
    return run, Step, StepKind


def test_atif_export_round_trips_usage():
    run, Step, StepKind = _run([])
    usage = {
        "input": 200,
        "cache_read": 600,
        "cache_write_5m": 200,
        "output": 200,
        "reasoning": 100,
    }
    run.steps = [
        Step(id="a", parent_ids=[], kind=StepKind.model, inputs={}, outputs={"text": "ok"},
             model_info="claude-sonnet-4-5", usage=usage, cost=0.5, provider="anthropic"),
        Step(id="b", parent_ids=["a"], kind=StepKind.tool, inputs={"name": "ls", "arguments": {}},
             outputs={"result": "f"}),
    ]  # fmt: skip
    document = to_atif(run)
    assert document["schema_version"] == "ATIF-v1.8"
    metrics = document["steps"][0]["metrics"]
    assert (metrics["prompt_tokens"], metrics["completion_tokens"]) == (1000, 300)
    assert document["final_metrics"]["total_steps"] == 2
    tool = document["steps"][1]
    assert (
        tool["observation"]["results"][0]["source_call_id"] == tool["tool_calls"][0]["tool_call_id"]
    )
    reimported = atif_events(json.dumps(document).splitlines())
    model = next(e for e in reimported if e.kind == "model")
    assert model.usage == usage


# -- OpenCode ---------------------------------------------------------------------------


def _opencode(tmp_path, *, drop=None):
    path = tmp_path / "opencode.db"
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT, parent_id TEXT, title TEXT,"
        " version TEXT, time_created INTEGER, time_updated INTEGER);"
        "CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, time_created INTEGER,"
        " time_updated INTEGER, data TEXT);"
        "CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT,"
        " time_created INTEGER, time_updated INTEGER, data TEXT);"
        "CREATE TABLE credential (id TEXT, value TEXT);"
        "INSERT INTO credential VALUES ('c', 'sk-secret-never-read');"
    )
    db.execute("INSERT INTO session VALUES ('ses_root', 'p', NULL, 't', '1.15.12', 1, 9)")
    db.execute("INSERT INTO session VALUES ('ses_kid', 'p', 'ses_root', 'k', '1.15.12', 3, 4)")
    assistant = {"role": "assistant", "agent": "build", "modelID": "claude-sonnet-4-5",
                 "providerID": "anthropic", "cost": 7.0,
                 "tokens": {"input": 100, "output": 20, "reasoning": 5,
                            "cache": {"read": 300, "write": 40}}}  # fmt: skip
    rows = [
        ("m1", "ses_root", 1000, {"role": "user"}),
        ("m2", "ses_root", 2000, assistant),
        ("m3", "ses_kid", 3000, dict(assistant, agent="explore")),
    ]
    for mid, sid, when, data in rows:
        db.execute(
            "INSERT INTO message VALUES (?, ?, ?, ?, ?)", (mid, sid, when, when, json.dumps(data))
        )
    parts = [
        ("p1", "m1", "ses_root", {"type": "text", "text": "fix it"}),
        ("p2", "m2", "ses_root", {"type": "text", "text": "on it"}),
        ("p3", "m2", "ses_root", {"type": "tool", "tool": "task", "callID": "call_1",
                                  "state": {"status": "completed", "input": {"prompt": "go"},
                                            "output": "ok", "metadata": {"sessionId": "ses_kid"}}}),
        ("p4", "m3", "ses_kid", {"type": "text", "text": "child"}),
    ]  # fmt: skip
    for pid, mid, sid, data in parts:
        db.execute("INSERT INTO part VALUES (?, ?, ?, 0, 0, ?)", (pid, mid, sid, json.dumps(data)))
    if drop:
        db.execute(f"DROP TABLE {drop}")
    db.commit()
    db.close()
    return path


def test_opencode_session_imports_with_exclusive_usage_and_linked_subagent(tmp_path):
    path = _opencode(tmp_path)
    before = path.read_bytes()
    fmt, events = detect_and_read(str(path), "auto")
    assert fmt == "opencode-session"
    assert path.read_bytes() == before  # opened read-only, nothing written
    model = next(e for e in events if e.kind == "model")
    assert model.usage == {"input": 100, "output": 20, "reasoning": 5, "cache_read": 300,
                           "cache_write_5m": 40}  # fmt: skip
    assert model.provider == "anthropic" and model.cost is None
    assert model.attributes["opencode.cost"] == 7.0
    by_id = {e.span_id: e for e in events}
    edge = next(e for e in events if e.kind == "subagent")
    assert by_id[edge.parent_span_id].actor == "task"
    child = [e for e in events if e.parent_span_id == edge.span_id]
    assert child and child[0].actor == "explore"
    assert "sk-secret" not in json.dumps([e.to_dict() for e in events], default=str)


def test_opencode_named_session_and_unknown_schema(tmp_path):
    path = _opencode(tmp_path)
    events = opencode_events(f"{path}::ses_kid")
    assert [e.kind for e in events] == ["model"]
    with pytest.raises(ValueError, match="no OpenCode session"):
        opencode_events(f"{path}::nope")
    other = tmp_path / "old"
    other.mkdir()
    with pytest.raises(ValueError, match="unsupported OpenCode database schema: no part table"):
        opencode_events(str(_opencode(other, drop="part")))


def test_opencode_symlinked_database_is_refused(tmp_path):
    link = tmp_path / "link.db"
    link.symlink_to(_opencode(tmp_path))
    with pytest.raises(ValueError, match="symlinked"):
        opencode_events(str(link))


def test_opencode_sessions_are_listed_from_the_default_location(tmp_path, monkeypatch):
    from opentine._cli_import_sessions import resolve

    (tmp_path / "opencode").mkdir()
    _opencode(tmp_path / "opencode")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    found = resolve("latest", "opencode-session")
    assert found.path.name == "opencode.db::ses_root"


# -- Hooks ------------------------------------------------------------------------------


def _hook_args(tmp_path, action, **extra):
    from opentine.repo import Repo

    repo = tmp_path / "repo"
    if not repo.exists():
        Repo.init(repo)
    values = {"action": action, "global_": True, "agent": None, "repo": str(repo),
              "dry_run": False}  # fmt: skip
    values.update(extra)
    return argparse.Namespace(**values)


def _homes(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "claude"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setenv("GEMINI_CLI_HOME", str(tmp_path / "gem"))


def test_hook_install_keeps_other_hooks_is_idempotent_and_uninstalls(tmp_path, monkeypatch):
    from opentine._cli_hook import cmd_hook

    _homes(tmp_path, monkeypatch)
    settings = tmp_path / "claude" / "settings.json"
    settings.parent.mkdir()
    theirs = {"theme": "dark", "hooks": {"SessionEnd": [{"hooks": [{"type": "command",
              "command": "notify-send bye"}]}], "Stop": [{"hooks": []}]}}  # fmt: skip
    settings.write_text(json.dumps(theirs))
    cmd_hook(_hook_args(tmp_path, "install"))
    installed = json.loads(settings.read_text())
    assert installed["theme"] == "dark" and installed["hooks"]["Stop"] == [{"hooks": []}]
    commands = [h["command"] for g in installed["hooks"]["SessionEnd"] for h in g["hooks"]]
    assert commands[0] == "notify-send bye" and MARKER in commands[1]
    assert "--format claude-code-transcript" in commands[1]
    assert json.loads((settings.parent / "settings.json.tine-backup").read_text()) == theirs
    cmd_hook(_hook_args(tmp_path, "install"))
    assert json.loads(settings.read_text()) == installed
    codex = json.loads((tmp_path / "codex" / "hooks.json").read_text())
    entry = codex["hooks"]["SessionEnd"][0]["hooks"][0]
    assert entry["timeout"] <= 3 and MARKER in entry["command"]
    cmd_hook(_hook_args(tmp_path, "uninstall"))
    assert json.loads(settings.read_text()) == theirs
    assert json.loads((tmp_path / "codex" / "hooks.json").read_text()) == {}


def test_hook_dry_run_writes_nothing_and_bad_config_is_refused(tmp_path, monkeypatch):
    from opentine._cli_hook import cmd_hook

    _homes(tmp_path, monkeypatch)
    cmd_hook(_hook_args(tmp_path, "install", dry_run=True))
    assert not (tmp_path / "claude").exists() and not (tmp_path / "codex").exists()
    broken = tmp_path / "claude" / "settings.json"
    broken.parent.mkdir()
    broken.write_text("{not json")
    with pytest.raises(SystemExit):
        cmd_hook(_hook_args(tmp_path, "install", agent=["claude-code"]))
    assert broken.read_text() == "{not json"


def test_hook_refuses_a_symlinked_config_and_a_missing_repo(tmp_path, monkeypatch):
    from opentine._cli_hook import cmd_hook

    target = tmp_path / "dotfiles.json"
    target.write_text("{}")
    link = tmp_path / "settings.json"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        read_config(link)
    _homes(tmp_path, monkeypatch)
    with pytest.raises(SystemExit):
        cmd_hook(_hook_args(tmp_path, "install", repo=str(tmp_path / "nowhere")))


def test_uninstall_without_our_hook_changes_nothing():
    document = {"hooks": {"SessionEnd": []}}
    assert without_ours(document) == (document, 0)
    assert without_ours({}) == ({}, 0)
    gemini = with_ours({}, AGENTS["gemini"], __import__("pathlib").Path("/r"))
    assert gemini["hooks"]["SessionEnd"][0]["hooks"][0]["timeout"] >= 1000


# -- End to end -------------------------------------------------------------------------


def test_atif_import_saves_priced_from_catalog_with_subagent_edges_and_exports_back(tmp_path):
    from opentine.cli import main
    from opentine.core import Run

    saved = tmp_path / "run.tine"
    main(["import", str(_write(tmp_path, _atif())), "--save", str(saved), "--price"])
    run = Run.load(saved)
    kinds = [step.v3_kind or step.kind.value for step in run.steps]
    assert kinds.count("subagent") == 1
    edge = next(step for step in run.steps if step.v3_kind == "subagent")
    children = [step for step in run.steps if edge.id in step.parent_ids]
    assert children and all(step.cost != 99.0 for step in run.steps)
    root_model = next(step for step in run.steps if step.model_info == "claude-sonnet-4-5")
    assert root_model.cost != 12.5  # catalog price, never the file's cost_usd
    out = tmp_path / "out.json"
    main(["export", str(saved), "--format", "atif", "--output", str(out)])
    document = json.loads(out.read_text())
    assert document["schema_version"] == "ATIF-v1.8"
    # 0.13: the subagent is an embedded trajectory, referenced from its tool result.
    (child,) = document["subagent_trajectories"]
    refs = [ref["trajectory_id"] for step in document["steps"]
            for result in (step.get("observation") or {}).get("results", [])
            for ref in result.get("subagent_trajectory_ref", [])]  # fmt: skip
    assert refs == [child["trajectory_id"]] and child["steps"]
    from opentine._atif import atif_events

    again = atif_events(out)
    assert sum(event.kind == "subagent" for event in again) == 1


def test_atif_export_refuses_an_endpoint(tmp_path):
    from opentine.cli import main

    saved = tmp_path / "run.tine"
    main(["import", str(_write(tmp_path, _atif())), "--save", str(saved)])
    with pytest.raises(SystemExit):
        main(["export", str(saved), "--format", "atif", "--endpoint", "https://example.invalid"])
