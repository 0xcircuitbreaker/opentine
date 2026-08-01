"""``tine repo-fork`` and ``tine repo-resume``: the v3 lineage verbs.

Phase 5 of the Surface Release adds the last two v3 verbs, and they are the only
ones whose names collide with legacy v2 commands — ``tine fork``/``tine resume``
still branch a ``.tine`` file, so these are prefixed. Four properties hold.

  * **They are the MCP tools.** v3 objects are content-addressed, so "the CLI
    fork and the ``fork_run_v3`` fork have the same oid" *is* byte-equality. The
    run-oid type check, the empty-tips refusal, and ``overrides={"resume": True}``
    are mirrored, not re-derived.
  * **Forking an older repository is a release gate.** Both verbs run against a
    copy of every committed golden repository from 0.3.0 on, and the copy must
    ``fsck`` clean afterwards. The committed fixtures are never mutated.
  * **``--ref`` is required, unconfined, and validated before any write.** The
    ``experiments/*`` confinement lives at the MCP boundary, whose threat model
    is model-controlled input; see tests/test_repo_cli_parity.py, which pins that
    divergence from both sides.
  * **``--json`` is a receipt.** It appears only after the write succeeded; every
    refusal is one ``tine <verb>: <message>`` line and exit 1, no JSON on stdout.

Everything runs in-process through ``opentine.cli.main`` — no subprocess.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from opentine import cli
from opentine.mcp_repository import register_repository_tools
from opentine.repository import Repo
from opentine.trace import Recorder, TraceEvent
from tests.test_mcp_repository import FakeMCP

COMPAT = Path(__file__).parent / "fixtures" / "compat"
VERSIONS = ("v0_3_0", "v0_4_0", "v0_5_0")
LINEAGE_VERBS = ("repo-fork", "repo-resume")


def _run(*args: str) -> None:
    cli.main(list(args))


def _refused(capsys, verb: str, *args: str) -> str:
    """Exit 1, exactly one stderr line, no JSON on stdout, no traceback."""
    with pytest.raises(SystemExit) as exited:
        _run(verb, *args)
    assert exited.value.code == 1
    captured = capsys.readouterr()
    assert captured.out.strip() == "", "a failed write must not print a JSON object"
    lines = [line for line in captured.err.splitlines() if line.strip()]
    assert len(lines) == 1, f"expected one refusal line, got {lines}"
    assert lines[0].startswith(f"tine {verb}: ")
    assert "Traceback" not in captured.err
    return lines[0]


def _json_out(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


@pytest.fixture
def fresh_repo(tmp_path: Path) -> tuple[Path, str, str]:
    """A repository this build wrote: its root, the run at ``heads/main``, an event."""
    root = tmp_path / "fresh"
    repo = Repo.init(root)
    recorder = Recorder.start(repo, capture=False)
    event = recorder.append(TraceEvent("model", 1, "trace", "span", outputs={"text": "hello"}))
    recorder.append(TraceEvent("model", 2, "trace", "span2", outputs={"text": "again"}))
    run = recorder.finalize()
    repo.update_ref("heads/main", run, expected_old=repo.read_ref("heads/main"))
    return root, run, event


@pytest.fixture(params=VERSIONS, ids=VERSIONS)
def golden_repo(request, tmp_path: Path) -> Path:
    """A released repository copied out of the source tree, never mutated in place."""
    dest = tmp_path / request.param
    shutil.copytree(COMPAT / request.param / "repo", dest)
    return dest


# --- the happy paths ---------------------------------------------------------


def test_repo_fork_branches_a_run_onto_the_named_ref(fresh_repo, capsys):
    root, run, event = fresh_repo
    _run(
        "repo-fork",
        "heads/main",
        "--repo",
        str(root),
        "--from-event",
        event,
        "--ref",
        "experiments/alt",
        "--json",
    )
    receipt = _json_out(capsys)
    repo = Repo.open(root)
    assert receipt["source_run_id"] == run and receipt["from_event"] == event
    assert receipt["ref"] == "experiments/alt"
    assert repo.read_ref("experiments/alt") == receipt["run_id"] != run
    # The fork keeps only the causal closure of the fork point, so the second
    # event is gone; that is the engine's behaviour, surfaced unchanged.
    assert repo.get(receipt["run_id"]).payload()["events"] == [event]
    assert repo.fsck(deep=True).ok


def test_repo_resume_forks_the_last_tip_into_a_running_run(fresh_repo, capsys):
    root, run, _ = fresh_repo
    tip = Repo.open(root).get(run).payload()["tips"][-1]
    _run("repo-resume", "heads/main", "--repo", str(root), "--ref", "experiments/live", "--json")
    receipt = _json_out(capsys)
    repo = Repo.open(root)
    assert receipt["from_event"] == tip and receipt["overrides"] == {"resume": True}
    assert receipt["resumed"] is True
    assert repo.get(receipt["run_id"]).payload()["status"] == "running"
    assert repo.read_ref("experiments/live") == receipt["run_id"]
    assert repo.fsck(deep=True).ok


def test_the_overrides_reach_the_forked_run(fresh_repo, capsys):
    root, _, event = fresh_repo
    _run(
        "repo-fork",
        "heads/main",
        "--repo",
        str(root),
        "--from-event",
        event,
        "--ref",
        "experiments/tuned",
        "--model",
        "claude-next",
        "--prompt",
        "try again, carefully",
        "--policy",
        '{"tools": ["safe"]}',
        "--json",
    )
    receipt = _json_out(capsys)
    assert receipt["overrides"] == {
        "model": "claude-next",
        "policy": {"tools": ["safe"]},
        "prompt": "try again, carefully",
    }
    repo = Repo.open(root)
    payload = repo.get(receipt["run_id"]).payload()
    assert b'"safe"' in repo.get(payload["manifests"]["policy"]).body
    assert b"carefully" in repo.get(payload["prompt_blob"]).body


def test_an_omitted_override_flag_forks_exactly_like_an_absent_key(fresh_repo, capsys):
    """None values are dropped by the engine, so the two spellings are one object."""
    root, run, event = fresh_repo
    plain = Repo.open(root).fork(run, event, overrides={}, ref="experiments/a")
    _run(
        "repo-fork",
        run,
        "--repo",
        str(root),
        "--from-event",
        event,
        "--ref",
        "experiments/b",
        "--json",
    )
    assert _json_out(capsys)["run_id"] == plain


@pytest.mark.parametrize("verb", LINEAGE_VERBS)
def test_both_verbs_accept_a_ref_or_a_bare_run_oid(fresh_repo, capsys, verb):
    root, run, event = fresh_repo
    extra = ("--from-event", event) if verb == "repo-fork" else ()
    _run(verb, "heads/main", "--repo", str(root), "--ref", "experiments/one", *extra, "--json")
    by_ref = _json_out(capsys)
    _run(verb, run, "--repo", str(root), "--ref", "experiments/two", *extra, "--json")
    by_oid = _json_out(capsys)
    assert by_ref["source_run_id"] == by_oid["source_run_id"] == run
    # Same source, same fork point, same overrides: content addressing makes it
    # literally the same object under two refs.
    assert by_ref["run_id"] == by_oid["run_id"]


# --- MCP parity: one object ---------------------------------------------------


def test_cli_repo_fork_writes_the_object_fork_run_v3_writes(fresh_repo, capsys):
    root, run, event = fresh_repo
    mcp = FakeMCP()
    register_repository_tools(mcp, str(root))
    expected = mcp.tools["fork_run_v3"](run, event, "experiments/mcp", policy={"tools": ["safe"]})
    _run(
        "repo-fork",
        "heads/main",
        "--repo",
        str(root),
        "--from-event",
        event,
        "--ref",
        "experiments/cli",
        "--policy",
        '{"tools": ["safe"]}',
        "--json",
    )
    assert _json_out(capsys)["run_id"] == expected["run_id"]


def test_cli_repo_resume_writes_the_object_resume_run_v3_writes(fresh_repo, capsys):
    root, run, _ = fresh_repo
    mcp = FakeMCP()
    register_repository_tools(mcp, str(root))
    expected = mcp.tools["resume_run_v3"](run, "experiments/mcp")
    _run("repo-resume", "heads/main", "--repo", str(root), "--ref", "experiments/cli", "--json")
    assert _json_out(capsys)["run_id"] == expected["run_id"]


# --- cross-version gate -------------------------------------------------------


def test_both_verbs_fork_every_released_repository_and_it_fscks(golden_repo, capsys):
    repo_arg = str(golden_repo)
    repo = Repo.open(golden_repo)
    run = repo.read_ref("heads/main")
    event = repo.get(run).payload()["events"][0]

    _run(
        "repo-fork",
        "heads/main",
        "--repo",
        repo_arg,
        "--from-event",
        event,
        "--ref",
        "experiments/cross-version",
        "--json",
    )
    forked = _json_out(capsys)["run_id"]

    _run("repo-resume", "heads/main", "--repo", repo_arg, "--ref", "experiments/resumed", "--json")
    resumed = _json_out(capsys)["run_id"]

    after = Repo.open(golden_repo)
    assert after.read_ref("experiments/cross-version") == forked
    assert after.read_ref("experiments/resumed") == resumed
    assert after.get(resumed).payload()["status"] == "running"
    result = after.fsck(deep=True)
    assert result.ok, result.errors
    # Reachable and typed, so counted rather than ignored.
    assert {forked, resumed} <= set(after.iter_oids())


def test_the_committed_fixtures_are_never_mutated(golden_repo, capsys):
    source = COMPAT / golden_repo.name / "repo"
    before = {
        path.relative_to(source): path.read_bytes() for path in source.rglob("*") if path.is_file()
    }
    _run("repo-resume", "heads/main", "--repo", str(golden_repo), "--ref", "experiments/x")
    capsys.readouterr()
    after = {
        path.relative_to(source): path.read_bytes() for path in source.rglob("*") if path.is_file()
    }
    assert before == after


# --- refusals -----------------------------------------------------------------


@pytest.mark.parametrize("verb", LINEAGE_VERBS)
def test_both_verbs_refuse_a_ref_that_names_no_run(fresh_repo, capsys, verb):
    root, _, event = fresh_repo
    extra = ("--from-event", event) if verb == "repo-fork" else ()
    message = _refused(
        capsys, verb, "heads/nope", "--repo", str(root), "--ref", "experiments/x", *extra
    )
    assert "cannot resolve heads/nope" in message


@pytest.mark.parametrize("verb", LINEAGE_VERBS)
def test_both_verbs_refuse_a_target_that_is_not_a_run(fresh_repo, capsys, verb):
    """The run-oid type check ``resume_run_v3`` performs, on both verbs."""
    root, _, event = fresh_repo
    extra = ("--from-event", event) if verb == "repo-fork" else ()
    message = _refused(capsys, verb, event, "--repo", str(root), "--ref", "experiments/x", *extra)
    assert "not a run object" in message


@pytest.mark.parametrize("verb", LINEAGE_VERBS)
def test_both_verbs_refuse_a_malformed_ref_before_writing_anything(fresh_repo, capsys, verb):
    root, _, event = fresh_repo
    extra = ("--from-event", event) if verb == "repo-fork" else ()
    before = set(Repo.open(root).iter_oids())
    message = _refused(
        capsys, verb, "heads/main", "--repo", str(root), "--ref", "../escape", *extra
    )
    assert "invalid ref name" in message
    # ``Repo.fork`` normalizes the ref only *after* storing the new run, so a
    # malformed ref would otherwise be reported once the object already existed.
    assert set(Repo.open(root).iter_oids()) == before


def test_repo_fork_refuses_a_fork_point_that_is_not_an_event(fresh_repo, capsys):
    root, run, _ = fresh_repo
    message = _refused(
        capsys,
        "repo-fork",
        "heads/main",
        "--repo",
        str(root),
        "--from-event",
        run,
        "--ref",
        "experiments/x",
    )
    assert "fork point must be an event id" in message


def test_repo_fork_refuses_an_event_from_another_run(fresh_repo, tmp_path, capsys):
    root, _, _ = fresh_repo
    other = Repo.init(tmp_path / "other")
    recorder = Recorder.start(other, capture=False)
    foreign = recorder.append(TraceEvent("model", 1, "t", "s", outputs={"text": "elsewhere"}))
    recorder.finalize()
    message = _refused(
        capsys,
        "repo-fork",
        "heads/main",
        "--repo",
        str(root),
        "--from-event",
        foreign,
        "--ref",
        "experiments/x",
    )
    assert "does not belong to source run" in message


@pytest.mark.parametrize(
    ("policy", "fragment"),
    [
        ("{oops", "must be valid JSON"),
        ('["a"]', "must be a JSON object"),
        ('"text"', "must be a JSON object"),
        ("7", "must be a JSON object"),
        ("null", "must be a JSON object"),
    ],
)
def test_repo_fork_refuses_a_policy_that_is_not_a_json_object(fresh_repo, capsys, policy, fragment):
    root, _, event = fresh_repo
    message = _refused(
        capsys,
        "repo-fork",
        "heads/main",
        "--repo",
        str(root),
        "--from-event",
        event,
        "--ref",
        "experiments/x",
        "--policy",
        policy,
    )
    assert fragment in message


def test_repo_resume_refuses_a_run_with_no_event_tip(tmp_path, capsys):
    """``tips[-1]`` on an empty list is an IndexError; both surfaces refuse by name."""
    root = tmp_path / "empty"
    repo = Repo.init(root)
    run = Recorder.start(repo, capture=False).finalize()
    assert repo.get(run).payload().get("tips") in (None, [], ())
    message = _refused(capsys, "repo-resume", run, "--repo", str(root), "--ref", "experiments/x")
    assert "no event tip" in message


# --- the human surface --------------------------------------------------------


def test_the_human_receipt_prints_the_new_oid_whole(fresh_repo, capsys):
    root, _, event = fresh_repo
    _run(
        "repo-fork",
        "heads/main",
        "--repo",
        str(root),
        "--from-event",
        event,
        "--ref",
        "experiments/human",
    )
    out = capsys.readouterr().out
    forked = Repo.open(root).read_ref("experiments/human")
    assert "Forked" in out and "experiments/human" in out
    # The receipt line is what an operator pastes into `tine object`, so it is
    # printed unshortened and unwrapped.
    assert forked in out.replace("\n", "")


def test_recorded_content_cannot_forge_markup_in_a_lineage_receipt(fresh_repo, capsys):
    root, _, event = fresh_repo
    _run(
        "repo-fork",
        "heads/main",
        "--repo",
        str(root),
        "--from-event",
        event,
        "--ref",
        "experiments/safe",
        "--prompt",
        "[/bold]\x1b]52;c;pwn\x1b\\ \x9b31m",
    )
    out = capsys.readouterr().out
    assert not {"\x1b", "\x9b", "\x00"} & set(out)
