"""The v3 query verbs: ``repo-diff`` and ``repo-search``.

Phase 3 of the Surface Release exposes two more engines that already existed and
were only reachable over MCP. The properties Phase 2 pinned hold here unchanged —
every verb runs over every released repository, recorded content reaches the
terminal sanitized, and a refusal is one stderr line — plus two this phase adds:

  * **The MCP defaults are the CLI defaults.** ``repo-search`` runs with
    ``successful_only=True`` and ``limit=20``, exactly as the ``search_runs``
    tool does, so an operator reproducing what an agent searched gets its result
    set rather than a different one.
  * **``--exit-code`` is git's contract.** 0 identical, 1 differs, and never 2 —
    argparse owns 2 for a usage error, and a caller branching on the status must
    be able to tell "the runs differ" from "you typed the command wrong".

Search is a scan bounded by ``MAX_SEARCH_OBJECTS`` (100,000 objects), which is a
documented latency property of the engine, not something this surface changes;
``opentine/repository/search.py`` is untouched by this phase.

Everything runs in-process through ``opentine.cli.main`` — no subprocess.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from opentine import cli
from opentine.repository import Repo
from opentine.repository import search as search_engine
from opentine.repository._run_blobs import json_blob

COMPAT = Path(__file__).parent / "fixtures" / "compat"
VERSIONS = ("v0_3_0", "v0_4_0", "v0_5_0")

#: Recorded content chosen to be hostile, identical to the Phase-2 suite: an
#: OSC-52 clipboard write, a CSI byte, a NUL, a bidi override, and a Rich end tag.
HOSTILE = "[/bold]\x1b]52;c;pwn\x1b\\ \x9b31m\x00 re‮versed ⁦iso⁩"
CONTROL = {"\x1b", "\x9b", "\x00", "‮", "⁦", "⁩"}


def _invoke(*args: str) -> None:
    cli.main([*args])


def _json_out(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


@pytest.fixture(params=VERSIONS, ids=VERSIONS)
def golden_repo(request, tmp_path: Path) -> Path:
    """A released repository copied out of the source tree, never mutated in place."""
    dest = tmp_path / request.param
    shutil.copytree(COMPAT / request.param / "repo", dest)
    return dest


# --- cross-version: repo-diff over every released repository -----------------


def test_repo_diff_renders_every_released_repository(golden_repo, capsys):
    _invoke("repo-diff", "heads/main", "heads/experiment", "--repo", str(golden_repo))
    out = capsys.readouterr().out
    # Every released fixture forks heads/experiment off heads/main, so the shape is
    # fixed: two shared events, two the mainline kept, none unique to the fork.
    assert "Diff: run:" in out and "only left" in out
    # The summary block, which is the half of SemanticDiff a table cannot show.
    for label in ("cost:", "latency:", "artifacts:", "evaluations:", "tool path:"):
        assert label in out


def test_repo_diff_json_over_every_released_repository(golden_repo, capsys):
    repo = Repo.open(golden_repo)
    _invoke(
        "repo-diff", "heads/main", "heads/experiment", "--repo", str(golden_repo), "--json"
    )  # fmt: skip
    payload = _json_out(capsys)
    assert payload["command"] == "repo-diff"
    assert payload["left"] == "heads/main" and payload["right"] == "heads/experiment"
    # The CLI-computed ids: what the engine actually compared, not what was typed.
    assert payload["left_id"] == repo.read_ref("heads/main")
    assert payload["right_id"] == repo.read_ref("heads/experiment")
    assert payload["identical"] is False
    # Every SemanticDiff field is present and untouched.
    assert {"common_events", "only_left", "only_right", "changed", "summary"} <= set(payload)
    assert len(payload["common_events"]) == 2 and len(payload["only_left"]) == 2
    assert payload["only_right"] == []
    assert set(payload["summary"]) == {
        "cost",
        "latency",
        "artifacts",
        "evaluations",
        "tool_path",
    }
    assert payload["summary"]["cost"]["left"] > payload["summary"]["cost"]["right"]


def test_repo_diff_json_matches_the_mcp_semantic_diff_tool(golden_repo, capsys):
    """The CLI must expose the engine, not a second opinion about it."""
    from dataclasses import asdict

    engine = asdict(Repo.open(golden_repo).diff("heads/main", "heads/experiment"))
    _invoke(
        "repo-diff", "heads/main", "heads/experiment", "--repo", str(golden_repo), "--json"
    )  # fmt: skip
    payload = _json_out(capsys)
    assert payload["common_events"] == list(engine["common_events"])
    assert payload["only_left"] == list(engine["only_left"])
    assert payload["summary"] == json.loads(json.dumps(engine["summary"]))


def test_repo_diff_accepts_run_oids_as_well_as_refs(golden_repo, capsys):
    repo = Repo.open(golden_repo)
    left, right = repo.read_ref("heads/main"), repo.read_ref("heads/experiment")
    _invoke("repo-diff", left, right, "--repo", str(golden_repo), "--json")
    payload = _json_out(capsys)
    assert payload["left"] == payload["left_id"] == left
    assert payload["right"] == payload["right_id"] == right


def test_repo_diff_of_a_run_against_itself_is_identical(golden_repo, capsys):
    _invoke("repo-diff", "heads/main", "heads/main", "--repo", str(golden_repo), "--json")
    payload = _json_out(capsys)
    assert payload["identical"] is True
    assert payload["only_left"] == payload["only_right"] == payload["changed"] == []


# --- --exit-code: git's contract, pinned -------------------------------------


def test_exit_code_is_zero_when_the_runs_are_identical(golden_repo, capsys):
    _invoke("repo-diff", "heads/main", "heads/main", "--repo", str(golden_repo), "--exit-code")
    assert "Diff: run:" in capsys.readouterr().out


def test_exit_code_is_one_when_the_runs_differ(golden_repo, capsys):
    argv = ("repo-diff", "heads/main", "heads/experiment", "--repo", str(golden_repo))

    with pytest.raises(SystemExit) as exited:
        _invoke(*argv, "--exit-code")

    assert exited.value.code == 1
    # The rendering still happened: --exit-code reports, it does not suppress.
    assert "only left" in capsys.readouterr().out


def test_a_differing_diff_exits_0_without_the_flag(golden_repo, capsys):
    # The default invocation must stay a plain read verb: only --exit-code may
    # turn a successful comparison into a non-zero status.
    _invoke("repo-diff", "heads/main", "heads/experiment", "--repo", str(golden_repo))
    assert "only left" in capsys.readouterr().out


def test_exit_code_still_emits_the_json_object(golden_repo, capsys):
    with pytest.raises(SystemExit) as exited:
        _invoke(
            "repo-diff",
            "heads/main",
            "heads/experiment",
            "--repo",
            str(golden_repo),
            "--json",
            "--exit-code",
        )

    assert exited.value.code == 1
    assert _json_out(capsys)["identical"] is False


def test_repo_diff_never_exits_2_on_an_engine_refusal(tmp_path, capsys):
    # 2 is argparse's usage status. A refusal that came back as 2 would be
    # indistinguishable from a mistyped command for any script branching on $?.
    Repo.init(tmp_path / "repo")

    with pytest.raises(SystemExit) as exited:
        _invoke("repo-diff", "heads/main", "heads/main", "--repo", str(tmp_path / "repo"))

    assert exited.value.code == 1
    assert capsys.readouterr().err.startswith("tine repo-diff: ")


def test_a_usage_error_is_still_argparse_status_2(capsys):
    with pytest.raises(SystemExit) as exited:
        _invoke("repo-diff", "only-one-side")
    assert exited.value.code == 2


# --- cross-version: repo-search over every released repository ---------------


def test_repo_search_renders_every_released_repository(golden_repo, capsys):
    _invoke("repo-search", "--repo", str(golden_repo))
    out = capsys.readouterr().out
    assert "repo-search: 1 run(s)" in out
    assert "completed" in out and "run:" in out


def test_repo_search_json_mirrors_the_mcp_defaults(golden_repo, capsys):
    _invoke("repo-search", "--repo", str(golden_repo), "--json")
    payload = _json_out(capsys)
    assert payload["command"] == "repo-search"  # not the legacy index "search" schema
    assert "runs" not in payload
    # The MCP search_runs defaults, mirrored exactly.
    assert payload["successful_only"] is True and payload["limit"] == 20
    assert payload["query"] == "" and payload["min_score"] is None and payload["model"] is None
    assert payload["count"] == len(payload["results"]) == 1
    assert set(payload["results"][0]) == {
        "run_id",
        "status",
        "score",
        "cost",
        "latency",
        "models",
        "matched_text",
    }
    assert payload["results"][0]["status"] == "completed"


def test_repo_search_json_matches_the_mcp_search_runs_tool(golden_repo, capsys):
    from dataclasses import asdict

    engine = [asdict(result) for result in Repo.open(golden_repo).search("")]
    _invoke("repo-search", "--repo", str(golden_repo), "--json")
    results = _json_out(capsys)["results"]
    assert [row["run_id"] for row in results] == [row["run_id"] for row in engine]
    assert [row["models"] for row in results] == [list(row["models"]) for row in engine]


def test_include_unsuccessful_flips_successful_only(golden_repo, capsys):
    # Every released fixture keeps heads/experiment at status "running", so the
    # flag is the difference between one row and two on all three of them.
    _invoke("repo-search", "--repo", str(golden_repo), "--include-unsuccessful", "--json")
    payload = _json_out(capsys)
    assert payload["successful_only"] is False
    assert payload["count"] == 2
    assert {row["status"] for row in payload["results"]} == {"completed", "running"}


def test_limit_bounds_the_result_set(golden_repo, capsys):
    repo = str(golden_repo)
    _invoke("repo-search", "--repo", repo, "--include-unsuccessful", "--limit", "1", "--json")
    payload = _json_out(capsys)
    assert payload["limit"] == 1 and payload["count"] == 1


def test_model_filter_is_a_substring_match(golden_repo, capsys):
    _invoke("repo-search", "--repo", str(golden_repo), "--model", "anthropic", "--json")
    assert _json_out(capsys)["count"] == 1
    _invoke("repo-search", "--repo", str(golden_repo), "--model", "no-such-vendor", "--json")
    assert _json_out(capsys)["count"] == 0


def test_min_score_filters_unevaluated_runs(golden_repo, capsys):
    # The fixtures carry no evaluation attestations, so every run scores None and
    # any --min-score removes them all; the flag must reach the engine to do that.
    _invoke("repo-search", "--repo", str(golden_repo), "--min-score", "0.5", "--json")
    payload = _json_out(capsys)
    assert payload["min_score"] == 0.5 and payload["count"] == 0


# --- untrusted repository content --------------------------------------------


def _hostile_repo(path: Path, *, text: str = HOSTILE) -> tuple[str, str]:
    """A completed run whose model, tool, and blob text are all attacker-chosen."""
    repo = Repo.init(path)
    outputs = json_blob(repo, {"text": text})
    event = repo.put(
        "event",
        {
            "cost": 1.0,
            "kind": "model",
            "model": HOSTILE,
            "output_blob": outputs,
            "parent_ids": [],
            "tool": {"name": HOSTILE},
        },
    )
    run = repo.put(
        "run",
        {
            "events": [event],
            "model": HOSTILE,
            "roots": [event],
            "status": "completed",
            "tips": [event],
        },
    )
    repo.update_ref("heads/main", run)
    return run, event


def test_repo_search_cannot_be_injected_by_matched_text(tmp_path, capsys):
    # matched_text is the rawest string on this surface: a prefix of blob bytes a
    # model read, echoed onto the operator's terminal.
    _hostile_repo(tmp_path / "repo", text=f"needle {HOSTILE}")

    _invoke("repo-search", "needle", "--repo", str(tmp_path / "repo"))

    out = capsys.readouterr().out
    assert not CONTROL & set(out), "matched blob text emitted a terminal control byte"
    assert "run:" in out  # the row was rendered, not dropped


def test_repo_diff_cannot_be_injected_by_recorded_content(tmp_path, capsys):
    repo_path = tmp_path / "repo"
    _hostile_repo(repo_path)
    repo = Repo.open(repo_path)
    # A second run with a differently-named tool, so a changed row renders too.
    event = repo.put(
        "event",
        {"cost": 2.0, "kind": "model", "model": HOSTILE, "parent_ids": [], "tool": {"n": HOSTILE}},
    )
    other = repo.put(
        "run",
        {"events": [event], "roots": [event], "status": "completed", "tips": [event]},
    )
    repo.update_ref("experiments/hostile", other)

    _invoke("repo-diff", "heads/main", "experiments/hostile", "--repo", str(repo_path))

    out = capsys.readouterr().out
    assert not CONTROL & set(out)
    assert "changed" in out  # the divergent pair reached the table


def test_hostile_content_survives_json_without_escaping(tmp_path, capsys):
    # --json is not a terminal: a consumer must see the bytes exactly as recorded.
    _hostile_repo(tmp_path / "repo", text=f"needle {HOSTILE}")
    _invoke("repo-search", "needle", "--repo", str(tmp_path / "repo"), "--json")
    result = _json_out(capsys)["results"][0]
    # models is a payload string, verbatim; matched_text is the *blob* prefix, so
    # it carries whatever canonical JSON escaping the recorder wrote. What matters
    # is that nothing the CLI does removes anything: the CSI byte and the bidi
    # overrides _terminal strips are still there, and so is the Rich end tag.
    assert result["models"] == [HOSTILE]
    matched = result["matched_text"]
    assert "needle" in matched and "[/bold]" in matched
    assert CONTROL & set(matched), "--json sanitized content it must pass through"


def test_a_hostile_query_cannot_inject_through_the_search_title(tmp_path, capsys):
    Repo.init(tmp_path / "repo")

    _invoke("repo-search", HOSTILE, "--repo", str(tmp_path / "repo"))

    assert not CONTROL & set(capsys.readouterr().out)


# --- refusals ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (("repo-diff", "heads/nope", "heads/nope"), "no such ref or object"),
        (("repo-diff", "not-an-oid", "not-an-oid"), "invalid ref name"),
        # Resolvable as an oid, but not a run: the engine's own type refusal.
        (("repo-diff", "blob:sha256:" + "0" * 64, "blob:sha256:" + "1" * 64), "requires a run"),
        (("repo-search", "--limit", "0"), "search limit must be between 1 and 1000"),
        (("repo-search", "--limit", "1001"), "search limit must be between 1 and 1000"),
        (("repo-search", "x" * 4097), "4096-character limit"),
    ],
)
def test_engine_refusals_surface_through_the_existing_envelope(tmp_path, capsys, argv, message):
    Repo.init(tmp_path / "repo")

    with pytest.raises(SystemExit) as exited:
        _invoke(*argv, "--repo", str(tmp_path / "repo"))

    assert exited.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith(f"tine {argv[0]}: ") and message in err
    assert "Traceback" not in err and err.count("\n") == 1


def test_a_search_aggregate_limit_refuses_cleanly(monkeypatch, tmp_path, capsys):
    """A bounded-scan refusal is a refusal, not a traceback.

    The aggregate text budget is squeezed rather than filled: reaching
    MAX_SEARCH_TEXT_TOTAL honestly would mean writing 16 MiB of blobs into a temp
    directory, and the code path taken is identical either way. search.py itself
    is not modified — the constant is read out of the module at call time.
    """
    _hostile_repo(tmp_path / "repo", text="needle in the haystack")
    monkeypatch.setattr(search_engine, "MAX_SEARCH_TEXT_TOTAL", 1)

    with pytest.raises(SystemExit) as exited:
        _invoke("repo-search", "needle", "--repo", str(tmp_path / "repo"))

    assert exited.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("tine repo-search: ")
    assert "aggregate text limit" in err
    assert "Traceback" not in err and err.count("\n") == 1


def test_search_over_an_empty_repository_is_an_empty_table(tmp_path, capsys):
    Repo.init(tmp_path / "repo")
    _invoke("repo-search", "--repo", str(tmp_path / "repo"), "--json")
    payload = _json_out(capsys)
    assert payload["count"] == 0 and payload["results"] == []
