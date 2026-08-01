"""D2: `tine import` over the existing importers, and `--json` on the read commands.

Two additive CLI capabilities are covered here, both driven through the public
entry point ``opentine.cli.main(argv)``:

* ``tine import`` must reach the *tested* importers in
  ``opentine.trace.importers`` rather than reimplement them, materialize their
  events with ``Recorder.import_events``, and persist the result as a portable
  v2 artifact and/or into a v3 repository.
* ``--json`` must emit one parseable object with the fields documented in
  ``opentine._cli_json`` while leaving the default human rendering untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Repo, Run, RunStatus, StepKind, cli
from opentine._cli_import import read_events
from opentine.trace import framework_events, otel_genai_events, to_otel_genai_document

HMAC_KEY = "d" * 40
KEY_ENV = "TINE_D2_KEY"
COMPAT = Path(__file__).parent / "fixtures" / "compat"
RELEASES = ("v0_3_0", "v0_4_0")

LANGCHAIN_RECORDS = [
    {
        "trace_id": "trace-1",
        "run_id": "chain-1",
        "parent_run_id": None,
        "name": "AgentExecutor",
        "type": "chain",
        "timestamp": 1_700_000_000,
        "inputs": {"input": "summarise the log"},
        "outputs": {"output": "summary"},
    },
    {
        "trace_id": "trace-1",
        "run_id": "llm-1",
        "parent_run_id": "chain-1",
        "name": "ChatOpenAI",
        "type": "llm",
        "timestamp": 1_700_000_001,
        "model": "gpt-4o",
        "usage": {"input": 12, "output": 7},
        "inputs": {"messages": [{"role": "user", "content": "hi"}]},
        "outputs": {"text": "hello"},
    },
]


def _source_run(run_id: str = "d2_source") -> Run:
    run = Run(id=run_id, model_info="mock-model", user_prompt="prompt")
    run.add_step(StepKind.think, {"text": "thinking"})
    run.add_step(
        StepKind.model, {"text": "ask"}, {"text": "answer"}, usage={"input": 9, "output": 3}
    )
    run.add_step(StepKind.tool, {"name": "grep", "arguments": {"pattern": "x"}}, {"text": "hit"})
    run.status = RunStatus.completed
    return run


@pytest.fixture
def workspace(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _otel_document(path: Path) -> Run:
    """Write an OTLP/JSON document produced by the D1 exporter; return its run."""
    run = _source_run()
    path.write_text(json.dumps(to_otel_genai_document(run)), encoding="utf-8")
    return run


# --------------------------------------------------------------------------- #
# tine import
# --------------------------------------------------------------------------- #


def test_otel_json_round_trips_through_the_cli_into_a_portable_artifact(workspace, capsys):
    document = workspace / "spans.json"
    source = _otel_document(document)
    output = workspace / "imported.tine"

    cli.main(["import", str(document), "--format", "otel-json", "--save", str(output)])

    # The Rich console wraps long paths, so compare against the unwrapped text.
    printed = capsys.readouterr().out.replace("\n", "")
    assert "# Imported" in printed and "3 event(s)" in printed
    assert str(output) in printed

    imported = Run.load(output)
    assert imported.status is RunStatus.completed
    assert len(imported.steps) == len(source.steps)
    assert [step.inputs for step in imported.steps] == [step.inputs for step in source.steps]
    assert [step.outputs for step in imported.steps] == [step.outputs for step in source.steps]
    assert imported.steps[2].kind is StepKind.tool
    assert imported.steps[1].usage == {"input": 9, "output": 3}
    # The run id the command printed is the one the artifact carries.
    assert imported.id in printed
    assert Run.verify_integrity(output).ok
    # Still an OTel-exportable run: the interop loop closes.
    assert len(otel_genai_events(to_otel_genai_document(imported))) == 3


def test_import_records_into_a_v3_repository_and_advances_the_ref(workspace, capsys):
    document = workspace / "spans.json"
    _otel_document(document)
    cli.main(["init", str(workspace / "repo")])
    capsys.readouterr()

    cli.main(
        [
            "import",
            str(document),
            "--format",
            "otel-json",
            "--repo",
            str(workspace / "repo"),
            "--ref",
            "heads/imported",
        ]
    )

    printed = capsys.readouterr().out
    assert "ref=heads/imported" in printed
    repo = Repo.open(workspace / "repo")
    run_id = repo.read_ref("heads/imported")
    assert run_id and run_id.startswith("run:")
    assert len(repo.load_run(run_id).steps) == 3


def test_import_writes_both_targets_from_one_invocation(workspace, capsys):
    document = workspace / "spans.json"
    _otel_document(document)
    cli.main(["init", str(workspace / "repo")])
    output = workspace / "both.tine"

    cli.main(
        [
            "import",
            str(document),
            "--format",
            "otel-json",
            "--repo",
            str(workspace / "repo"),
            "--save",
            str(output),
        ]
    )
    capsys.readouterr()

    repo = Repo.open(workspace / "repo")
    from_repo = repo.load_run(repo.read_ref("heads/main"))
    assert Run.load(output).id == from_repo.id


@pytest.mark.parametrize("as_array", [True, False])
def test_framework_log_sample_imports_as_array_or_jsonl(workspace, capsys, as_array):
    log = workspace / ("records.json" if as_array else "records.jsonl")
    log.write_text(
        json.dumps(LANGCHAIN_RECORDS)
        if as_array
        else "\n".join(json.dumps(record) for record in LANGCHAIN_RECORDS),
        encoding="utf-8",
    )
    output = workspace / "langchain.tine"

    cli.main(["import", str(log), "--format", "langchain", "--save", str(output)])
    capsys.readouterr()

    imported = Run.load(output)
    assert len(imported.steps) == 2
    assert imported.steps[1].parent_ids == [imported.steps[0].id]
    assert imported.steps[1].model_info == "gpt-4o"
    assert imported.steps[1].usage == {"input": 12, "output": 7}


def test_jsonl_trace_events_import_from_stdin(workspace, capsys, monkeypatch):
    lines = [
        {"kind": "model", "span_id": "s1", "trace_id": "t", "inputs": {"text": "q"}},
        {"kind": "tool", "span_id": "s2", "trace_id": "t", "parent_span_id": "s1"},
    ]
    stdin = workspace / "events.jsonl"
    stdin.write_text("\n".join(json.dumps(line) for line in lines), encoding="utf-8")
    output = workspace / "stdin.tine"
    with stdin.open("r", encoding="utf-8") as handle:
        monkeypatch.setattr("sys.stdin", handle)
        cli.main(["import", "-", "--format", "jsonl", "--save", str(output)])
    capsys.readouterr()

    imported = Run.load(output)
    assert [step.kind for step in imported.steps] == [StepKind.model, StepKind.tool]


def test_otel_json_imports_from_stdin(workspace, capsys, monkeypatch):
    document = workspace / "spans.json"
    _otel_document(document)
    output = workspace / "piped.tine"
    with document.open("rb") as handle:
        monkeypatch.setattr("sys.stdin", handle)
        cli.main(["import", "-", "--format", "otel-json", "--save", str(output)])
    capsys.readouterr()

    assert len(Run.load(output).steps) == 3


def test_the_cli_reuses_the_tested_importers_verbatim(workspace):
    """Routing, not reimplementation: same bytes, same events as a direct call."""
    document = workspace / "spans.json"
    _otel_document(document)
    log = workspace / "records.json"
    log.write_text(json.dumps(LANGCHAIN_RECORDS), encoding="utf-8")

    assert read_events(str(document), "otel-json") == otel_genai_events(
        json.loads(document.read_text(encoding="utf-8"))
    )
    assert read_events(str(log), "langchain") == framework_events(LANGCHAIN_RECORDS, "langchain")


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ([], "Nothing to write"),
        (["--save", "out.tine", "--ref", "heads/main"], "--ref has no effect without --repo"),
        (["--repo", "repo", "--force"], "--force has no effect without --save"),
    ],
)
def test_import_refuses_a_flag_it_cannot_honour(workspace, capsys, extra, message):
    document = workspace / "spans.json"
    _otel_document(document)
    cli.main(["init", str(workspace / "repo")])
    capsys.readouterr()

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["import", str(document), "--format", "otel-json", *extra])

    assert exit_info.value.code == 1
    assert message in capsys.readouterr().out.replace("\n", " ")


def test_import_refuses_to_overwrite_an_artifact_without_force(workspace, capsys):
    document = workspace / "spans.json"
    _otel_document(document)
    output = workspace / "taken.tine"
    output.write_text("do not clobber me", encoding="utf-8")

    with pytest.raises(SystemExit):
        cli.main(["import", str(document), "--format", "otel-json", "--save", str(output)])

    assert "Refusing to overwrite" in capsys.readouterr().out
    assert output.read_text(encoding="utf-8") == "do not clobber me"

    cli.main(["import", str(document), "--format", "otel-json", "--save", str(output), "--force"])
    capsys.readouterr()
    assert Run.load(output).steps


def test_a_recognized_but_empty_source_is_reported_separately(workspace, capsys):
    """A wrong --format reads fine and yields nothing; say so, not "Import failed"."""
    empty = workspace / "empty.json"
    empty.write_text(json.dumps({"resourceSpans": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["import", str(empty), "--format", "otel-json", "--save", str(workspace / "x")])

    assert exit_info.value.code == 1
    printed = capsys.readouterr().out.replace("\n", "")
    assert "No trace events found" in printed and "--format otel-json" in printed
    assert not (workspace / "x").exists()


def test_unreadable_source_is_a_refusal_not_a_traceback(workspace, capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["import", str(workspace / "absent.json"), "--format", "otel-json", "--save", "x"])

    assert exit_info.value.code == 1
    assert "Import failed" in capsys.readouterr().out


def test_a_malformed_jsonl_record_names_its_line(workspace, capsys):
    log = workspace / "broken.jsonl"
    log.write_text(json.dumps(LANGCHAIN_RECORDS[0]) + "\nnot json\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["import", str(log), "--format", "langchain", "--save", str(workspace / "x")])

    assert exit_info.value.code == 1
    assert "line 2 is not valid JSON" in capsys.readouterr().out.replace("\n", "")


# --------------------------------------------------------------------------- #
# --json on the read commands
# --------------------------------------------------------------------------- #


def _json_out(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


def test_show_json_carries_the_documented_fields(workspace, capsys):
    path = workspace / "run.tine"
    _source_run().save(path)

    cli.main(["show", str(path), "--json"])
    payload = _json_out(capsys)

    assert payload["command"] == "show"
    assert payload["path"] == str(path)
    assert set(payload["run"]) == {
        "id",
        "short_id",
        "status",
        "model",
        "created_at",
        "total_cost",
        "step_count",
        "tags",
        "user_prompt",
        "system_prompt",
    }
    assert payload["run"]["step_count"] == 3
    assert set(payload["steps"][0]) == {
        "id",
        "short_id",
        "kind",
        "parent_ids",
        "model",
        "cost",
        "duration",
        "timestamp",
        "inputs",
        "outputs",
        "usage",
        "billing",
        "error",
        "tool",
    }
    assert [step["kind"] for step in payload["steps"]] == ["think", "model", "tool"]


def test_verify_json_reports_integrity_and_signature(workspace, capsys, monkeypatch):
    monkeypatch.setenv(KEY_ENV, HMAC_KEY)
    plain, signed = workspace / "plain.tine", workspace / "signed.tine"
    run = _source_run()
    run.save(plain)
    run.save(signed, sign_key=HMAC_KEY.encode(), sign_algorithm="hmac-sha256")

    cli.main(["verify", str(plain), "--json"])
    payload = _json_out(capsys)
    assert payload["command"] == "verify" and payload["ok"] is True
    assert payload["signature"] is None
    assert set(payload["integrity"]) == {
        "ok",
        "algorithm",
        "expected",
        "actual",
        "reason",
        "draft",
    }

    cli.main(["verify", str(signed), "--json", "--key-env", KEY_ENV])
    signature = _json_out(capsys)["signature"]
    assert signature["ok"] is True and signature["algorithm"] == "hmac-sha256"
    assert set(signature) == {
        "ok",
        "state",
        "algorithm",
        "key_id",
        "signer",
        "signed_at",
        "reason",
    }


def test_verify_json_emits_an_object_when_the_check_fails(workspace, capsys, monkeypatch):
    monkeypatch.setenv(KEY_ENV, HMAC_KEY)
    path = workspace / "tampered.tine"
    _source_run().save(path, sign_key=HMAC_KEY.encode(), sign_algorithm="hmac-sha256")
    path.write_text(
        path.read_text(encoding="utf-8").replace("answer", "forged", 1), encoding="utf-8"
    )

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["verify", str(path), "--json", "--key-env", KEY_ENV])

    assert exit_info.value.code == 1
    payload = _json_out(capsys)
    assert payload["ok"] is False and payload["integrity"]["ok"] is False
    assert payload["integrity"]["reason"]
    # Integrity is the gate in both renderings: no authenticity claim beside a
    # failed digest, so the human path and the JSON path stop at the same point.
    assert payload["signature"] is None


def test_ls_and_search_json_carry_index_rows(workspace, capsys):
    runs = workspace / ".tine_runs"
    runs.mkdir()
    run = _source_run()
    run.add_tag("prod")
    run.save(runs / "d2.tine")

    cli.main(["ls", "--json"])
    listing = _json_out(capsys)
    assert listing["command"] == "ls" and listing["count"] == 1
    assert set(listing["runs"][0]) == {
        "run_id",
        "short_id",
        "status",
        "model",
        "steps",
        "cost",
        "created_at",
        "mtime",
        "format_version",
        "tags",
        "file",
        "unreadable",
    }
    assert listing["runs"][0]["tags"] == ["prod"]

    cli.main(["search", "tag:prod", "--json"])
    found = _json_out(capsys)
    assert found["command"] == "search" and found["query"] == "tag:prod"
    assert [row["run_id"] for row in found["runs"]] == [run.id]

    cli.main(["search", "tag:absent", "--json"])
    assert _json_out(capsys) == {"command": "search", "count": 0, "query": "tag:absent", "runs": []}


def test_verify_json_reports_a_target_it_cannot_read_at_all(workspace, capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["verify", "no-such-run", "--json"])

    assert exit_info.value.code == 1
    payload = _json_out(capsys)
    assert payload["ok"] is False and payload["path"] == "no-such-run"
    assert payload["signature"] is None


def test_cost_json_exits_one_on_a_recorded_budget_breach(workspace, capsys):
    path = workspace / "breached.tine"
    run = _source_run()
    run.metadata["budget_state"] = {
        "breached": True,
        "dimension": "cost",
        "limit": 1.0,
        "incurred": 2.0,
    }
    run.save(path)

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["cost", str(path), "--json"])

    assert exit_info.value.code == 1
    payload = _json_out(capsys)
    assert payload["over_budget"] is True
    assert payload["budget_state"]["dimension"] == "cost"


def test_cost_json_carries_the_documented_fields(workspace, capsys):
    path = workspace / "run.tine"
    _source_run().save(path)

    cli.main(["cost", str(path), "--json"])
    payload = _json_out(capsys)

    assert set(payload) == {
        "command",
        "run_id",
        "short_id",
        "total_cost",
        "total_tokens",
        "input_tokens",
        "output_tokens",
        "by_model",
        "by_kind",
        "budget",
        "budget_state",
        "over_budget",
        "pricing",
    }
    assert payload["command"] == "cost"
    assert payload["total_tokens"] == 12
    assert payload["over_budget"] is False and payload["budget"] is None
    # A run with nothing pinned reports complete rather than "unknown": absence of
    # a pricing record is not evidence of an unpriced step (see _runtime_accounting).
    assert payload["pricing"] == {
        "complete": True,
        "unpriced_steps": 0,
        "unpriced_providers": [],
    }


@pytest.mark.parametrize("release", RELEASES)
def test_json_and_import_read_runs_from_every_supported_release(workspace, capsys, release):
    """Backwards-compat gate: from 0.3.0 on, newer opentine reads older stored data.

    Neither capability may narrow that: ``--json`` is a second rendering of what
    the loaders already return, and ``import`` writes ordinary runs.
    """
    artifact = COMPAT / release / "artifact.tine"
    expected = len(Run.load(artifact).steps)

    cli.main(["show", str(artifact), "--json"])
    shown = _json_out(capsys)
    assert shown["run"]["step_count"] == expected

    cli.main(["verify", str(artifact), "--json"])
    assert _json_out(capsys)["ok"] is True

    cli.main(["cost", str(artifact), "--json"])
    assert _json_out(capsys)["command"] == "cost"

    document = workspace / f"{release}.json"
    document.write_text(json.dumps(to_otel_genai_document(Run.load(artifact))), encoding="utf-8")
    output = workspace / f"{release}.tine"
    cli.main(["import", str(document), "--format", "otel-json", "--save", str(output)])
    capsys.readouterr()
    assert len(Run.load(output).steps) == expected


def test_human_rendering_is_unchanged_when_json_is_absent(workspace, capsys):
    runs = workspace / ".tine_runs"
    runs.mkdir()
    path = runs / "human.tine"
    _source_run().save(path)

    for argv in (["show", str(path)], ["cost", str(path)], ["verify", str(path)], ["ls"]):
        cli.main(argv)
        printed = capsys.readouterr().out
        assert printed.strip()
        with pytest.raises(ValueError):
            json.loads(printed)

    cli.main(["cost", str(path)])
    assert "# Cost" in capsys.readouterr().out
    cli.main(["verify", str(path)])
    assert "OK" in capsys.readouterr().out
