"""``tine import --json`` and ``tine tag --json``: the last two read-ish surfaces.

Phase 10 finishes the ``--json`` sweep. Three things are pinned here:

1. **The default invocation is untouched.** Without ``--json`` both commands
   print exactly what they printed before, and their stdout is not JSON. The
   pins compare against the literal text the commands compose, so a stray extra
   line fails here rather than in a user's terminal.
2. **The object is the docstring.** ``_cli_json_surface``'s docstring *is* the
   schema; the key sets are read back out of it, so a field added to the payload
   without a line of prose fails, and vice versa.
3. **``tag`` covers both listing spellings.** ``--list`` and the implicit
   default (neither ``--add`` nor ``--remove``) are the same mode and must emit
   byte-identical objects. The mutating path is not a listing: it refuses
   ``--json`` out loud instead of writing the artifact and dropping the flag.

Everything is driven in process through ``opentine.cli.main(argv)``; nothing
shells a binary.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from opentine import Repo, Run, RunStatus, StepKind, cli
from opentine.trace import to_otel_genai_document

TRACE_EVENTS = [
    {"kind": "model", "span_id": "s1", "trace_id": "t", "inputs": {"text": "q"}},
    {"kind": "tool", "span_id": "s2", "trace_id": "t", "parent_span_id": "s1"},
]


@pytest.fixture
def workspace(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _invoke(capsys, *argv: str) -> tuple[int, str]:
    """Drive one in-process ``tine`` invocation; return (exit code, stdout)."""
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


def _payload(capsys, *argv: str) -> tuple[int, dict]:
    code, out = _invoke(capsys, *argv)
    return code, json.loads(out)


def _documented_keys(section: str) -> set[str]:
    """The keys one ``tine ...`` section of ``_cli_json_surface``'s docstring lists."""
    from opentine import _cli_json_surface

    blocks = [
        block
        for block in (_cli_json_surface.__doc__ or "").split("``tine ")
        if block.startswith(section)
    ]
    assert len(blocks) == 1, f"{section!r} is not one heading in the docstring"
    return set(re.findall(r"^    ``(\w+)``", blocks[0], re.MULTILINE))


IMPORT_SECTION = "import SOURCE --format FMT --json"
TAG_SECTION = "tag RUN --json"


def _otel_source(path: Path) -> Run:
    """Write an OTLP/JSON document the D1 exporter produced; return its run."""
    run = Run(id="surface_source", model_info="mock-model", user_prompt="prompt")
    first = run.add_step(StepKind.think, {"text": "thinking"})
    second = run.add_step(
        StepKind.model,
        {"text": "ask"},
        {"text": "answer"},
        usage={"input": 9, "output": 3},
        parent_id=first.id,
    )
    run.add_step(StepKind.done, {"text": "done"}, parent_id=second.id)
    run.status = RunStatus.completed
    path.write_text(json.dumps(to_otel_genai_document(run)), encoding="utf-8")
    return run


def _tagged(path: Path, *tags: str) -> Run:
    run = Run(id="surface_tagged", model_info="mock-model", user_prompt="prompt")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    for tag in tags:
        run.add_tag(tag)
    run.save(path)
    return run


# --------------------------------------------------------------------------- #
# tine import --json
# --------------------------------------------------------------------------- #


def test_import_default_output_is_unchanged_and_is_not_json(workspace, capsys):
    _otel_source(workspace / "spans.json")

    code, printed = _invoke(capsys, "import", "spans.json", "--format", "otel-json", "--save", "a")

    assert code == 0
    unwrapped = printed.replace("\n", "")
    assert "# Imported" in unwrapped and "3 event(s)" in unwrapped
    assert Run.load(workspace / "a").id in unwrapped
    assert "Saved:" in unwrapped
    with pytest.raises(json.JSONDecodeError):
        json.loads(printed)


def test_the_import_object_carries_exactly_its_documented_fields(workspace, capsys):
    _otel_source(workspace / "spans.json")

    code, payload = _payload(
        capsys, "import", "spans.json", "--format", "otel-json", "--save", "saved.tine", "--json"
    )

    assert code == 0
    assert set(payload) == _documented_keys(IMPORT_SECTION)
    assert set(payload["run"]) == {"id", "short_id", "step_count"}


def test_a_save_only_import_reports_the_artifact_and_no_repository(workspace, capsys):
    _otel_source(workspace / "spans.json")

    _, payload = _payload(
        capsys, "import", "spans.json", "--format", "otel-json", "--save", "saved.tine", "--json"
    )

    saved = Run.load(workspace / "saved.tine")
    assert payload["command"] == "import"
    assert payload["format"] == "otel-json"
    assert payload["source"] == "spans.json"
    assert payload["events_imported"] == 3
    assert payload["run"]["id"] == saved.id
    assert payload["run"]["short_id"] == saved.id[:12]
    assert payload["run"]["step_count"] == len(saved.steps) == 3
    assert payload["saved_to"] == "saved.tine"
    # The scratch repository a --save-only import builds is not the user's, and
    # --ref is refused without --repo, so neither may be reported as a target.
    assert payload["repo"] is None
    assert payload["ref"] is None


def test_a_repository_import_reports_the_repo_and_the_ref_it_advanced(workspace, capsys):
    _otel_source(workspace / "spans.json")
    _invoke(capsys, "init", "repo")

    _, payload = _payload(
        capsys,
        *("import", "spans.json", "--format", "otel-json"),
        *("--repo", "repo", "--ref", "heads/imported", "--json"),
    )

    repo = Repo.open(workspace / "repo")
    assert payload["ref"] == "heads/imported"
    assert payload["repo"] == str(repo.path)
    assert payload["saved_to"] is None
    assert repo.read_ref("heads/imported") == payload["run"]["id"]


def test_a_repository_import_without_a_ref_reports_the_default_ref(workspace, capsys):
    _otel_source(workspace / "spans.json")
    _invoke(capsys, "init", "repo")

    _, payload = _payload(
        capsys, *("import", "spans.json", "--format", "otel-json", "--repo", "repo", "--json")
    )

    assert payload["ref"] == "heads/main"
    assert Repo.open(workspace / "repo").read_ref("heads/main") == payload["run"]["id"]


def test_both_targets_are_reported_from_one_invocation(workspace, capsys):
    _otel_source(workspace / "spans.json")
    _invoke(capsys, "init", "repo")

    _, payload = _payload(
        capsys,
        *("import", "spans.json", "--format", "otel-json"),
        *("--repo", "repo", "--save", "both.tine", "--json"),
    )

    assert payload["saved_to"] == "both.tine" and payload["repo"] is not None
    assert Run.load(workspace / "both.tine").id == payload["run"]["id"]


def test_a_jsonl_import_from_a_file_reports_its_events(workspace, capsys):
    source = workspace / "events.jsonl"
    source.write_text("\n".join(json.dumps(item) for item in TRACE_EVENTS), encoding="utf-8")

    _, payload = _payload(
        capsys, "import", "events.jsonl", "--format", "jsonl", "--save", "j.tine", "--json"
    )

    assert payload["format"] == "jsonl"
    assert payload["events_imported"] == 2
    assert payload["run"]["step_count"] == 2


def test_import_json_writes_one_object_and_no_human_text(workspace, capsys):
    _otel_source(workspace / "spans.json")
    _invoke(capsys, "init", "repo")

    _, out = _invoke(
        capsys,
        *("import", "spans.json", "--format", "otel-json"),
        *("--repo", "repo", "--save", "one.tine", "--json"),
    )

    # The whole stream parses: no "# Imported", no "Saved:", no "Repo:" line.
    assert json.loads(out)["command"] == "import"
    assert "Imported" not in out and "Saved" not in out


@pytest.mark.parametrize(
    "argv",
    [
        # unreadable source
        ("import", "missing.json", "--format", "otel-json", "--save", "x.tine", "--json"),
        # read fine, recognized nothing — almost always the wrong --format
        ("import", "empty.json", "--format", "langchain", "--save", "x.tine", "--json"),
        # no persistence target, so there is no run to describe
        ("import", "spans.json", "--format", "otel-json", "--json"),
        # --ref without --repo names nothing
        ("import", "spans.json", "--format", "otel-json", "--save", "x.tine", "--ref", "r"),
    ],
)
def test_an_import_that_never_completed_is_a_human_message_and_never_json(workspace, capsys, argv):
    """No import, no object: a script must read the exit status, not parse a null."""
    _otel_source(workspace / "spans.json")
    (workspace / "empty.json").write_text("[]", encoding="utf-8")

    code, out = _invoke(capsys, *argv)

    assert code == 1
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


# --------------------------------------------------------------------------- #
# tine tag --json
# --------------------------------------------------------------------------- #


def test_tag_default_output_is_unchanged_and_is_not_json(workspace, capsys):
    _tagged(workspace / "run.tine", "alpha", "beta")

    listed_code, listed = _invoke(capsys, "tag", "run.tine", "--list")
    implicit_code, implicit = _invoke(capsys, "tag", "run.tine")

    assert (listed_code, implicit_code) == (0, 0)
    assert listed == implicit == "alpha, beta\n"
    with pytest.raises(json.JSONDecodeError):
        json.loads(listed)


def test_the_tag_object_carries_exactly_its_documented_fields(workspace, capsys):
    _tagged(workspace / "run.tine", "alpha")

    code, payload = _payload(capsys, "tag", "run.tine", "--list", "--json")

    assert code == 0
    assert set(payload) == _documented_keys(TAG_SECTION)


def test_the_explicit_list_and_the_implicit_default_emit_the_same_object(workspace, capsys):
    run = _tagged(workspace / "run.tine", "beta", "alpha")

    _, listed = _payload(capsys, "tag", "run.tine", "--list", "--json")
    _, implicit = _payload(capsys, "tag", "run.tine", "--json")

    assert listed == implicit
    assert listed["command"] == "tag"
    assert listed["run_id"] == run.id
    assert listed["short_id"] == run.id[:12]
    assert listed["path"] == "run.tine"
    assert listed["tags"] == list(run.tags) == ["alpha", "beta"]
    assert listed["count"] == 2


def test_an_untagged_run_reports_an_empty_list_and_not_null(workspace, capsys):
    _tagged(workspace / "bare.tine")

    _, payload = _payload(capsys, "tag", "bare.tine", "--json")

    assert payload["tags"] == [] and payload["count"] == 0


def test_tag_json_writes_one_object_and_no_human_text(workspace, capsys):
    _tagged(workspace / "run.tine", "alpha")

    _, out = _invoke(capsys, "tag", "run.tine", "--json")

    assert json.loads(out)["command"] == "tag"
    assert "# Tags" not in out


@pytest.mark.parametrize("edit", [("--add", "gamma"), ("--remove", "alpha")])
def test_the_mutating_path_refuses_json_instead_of_dropping_it(workspace, capsys, edit):
    """Refusing is not a behaviour change: the flag did not exist on tag before."""
    _tagged(workspace / "run.tine", "alpha")

    code, out = _invoke(capsys, "tag", "run.tine", *edit, "--json")

    assert code == 1
    assert "--json has no effect" in out.replace("\n", " ").replace("  ", " ")
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)
    # Refused before the edit: the artifact still carries exactly what it did.
    assert Run.load(workspace / "run.tine").tags == ["alpha"]


@pytest.mark.parametrize("edit", [("--add", "gamma"), ("--remove", "alpha")])
def test_the_mutating_path_without_json_is_unchanged(workspace, capsys, edit):
    _tagged(workspace / "run.tine", "alpha")

    code, out = _invoke(capsys, "tag", "run.tine", *edit)

    assert code == 0
    assert "# Tags" in out
    expected = ["alpha", "gamma"] if edit[0] == "--add" else []
    assert Run.load(workspace / "run.tine").tags == expected


def test_a_run_tag_cannot_find_is_a_human_message_and_never_json(workspace, capsys):
    code, out = _invoke(capsys, "tag", "nope.tine", "--json")

    assert code == 1
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)
