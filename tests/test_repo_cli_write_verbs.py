"""The v3 operator write verbs: ``attest``, ``evaluate``, and ``promote``.

Phase 4 of the Surface Release exposes the mutating half of the repository — the
half MCP withholds by default. Four properties have to hold.

  * **Cross-version writing is a release gate.** Reading an older repository is
    already gated; from 0.6.0 on, *appending* to one is too. Every verb runs
    against a copy of every committed golden repository (>= 0.3.0), and the copy
    must ``fsck`` clean afterwards. This is also the first cross-version exercise
    of the evaluation-score read path: the score written here is read back
    through ``repo-search`` and through ``semantic_diff``'s association scan.
  * **The CLI and MCP write the same object.** v3 objects are content-addressed,
    so "the CLI attestation and the MCP attestation have the same oid" *is*
    byte-equality. There is exactly one evaluation claim shape.
  * **A promotion is a release gate.** ``expected_old=None`` means *expect no
    existing ref*, so moving an existing promotion requires ``--expected-old``,
    the refusal says so, and no ``--force`` exists anywhere.
  * **``--json`` is a receipt.** It is emitted only after the write succeeded;
    every refusal is one ``tine <verb>: <message>`` line and exit 1, with no
    traceback and no JSON object on stdout.

Everything runs in-process through ``opentine.cli.main`` — no subprocess.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from opentine import cli
from opentine._repo_cli_parser import add_repo_parsers
from opentine.mcp_repository import register_repository_tools
from opentine.repository import Repo, ops
from opentine.trace import Recorder, TraceEvent
from tests.test_mcp_repository import FakeMCP

COMPAT = Path(__file__).parent / "fixtures" / "compat"
VERSIONS = ("v0_3_0", "v0_4_0", "v0_5_0")

WRITE_VERBS = ("attest", "evaluate", "promote")


def _run(*args: str) -> None:
    """One in-process invocation; ``cli.main`` takes argv directly."""
    cli.main(list(args))


def _refused(capsys, verb: str, *args: str) -> str:
    """Assert the verb refuses cleanly: exit 1, one stderr line, no JSON stdout."""
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


@pytest.fixture(params=VERSIONS, ids=VERSIONS)
def golden_repo(request, tmp_path: Path) -> Path:
    """A released repository copied out of the source tree, never mutated in place."""
    dest = tmp_path / request.param
    shutil.copytree(COMPAT / request.param / "repo", dest)
    return dest


@pytest.fixture
def fresh_repo(tmp_path: Path) -> tuple[Path, str]:
    """A repository this build wrote, plus the run oid ``heads/main`` points at."""
    root = tmp_path / "fresh"
    repo = Repo.init(root)
    recorder = Recorder.start(repo, capture=False)
    recorder.append(TraceEvent("model", 1, "trace", "span", outputs={"text": "hello"}))
    run = recorder.finalize()
    repo.update_ref("heads/main", run, expected_old=repo.read_ref("heads/main"))
    return root, run


# --- the resolve_target rename ----------------------------------------------


def test_resolve_target_is_public_and_the_private_name_is_gone():
    # attest hands target_id to repo.put and promote hands its run into update_ref;
    # both need an oid, so the resolver had to stop being private to the engine.
    assert callable(ops.resolve_target)
    assert not hasattr(ops, "_resolve"), "the private alias must not linger as a second name"


def test_resolve_target_still_passes_an_oid_through_and_reports_a_missing_ref(fresh_repo):
    root, run = fresh_repo
    repo = Repo.open(root)
    assert ops.resolve_target(repo, run) == run
    assert ops.resolve_target(repo, "heads/main") == run
    with pytest.raises(KeyError):
        ops.resolve_target(repo, "heads/nope")


def test_attest_and_promote_accept_a_ref_which_is_the_whole_point(fresh_repo, capsys):
    # Before the rename these two failed on a ref: put refused an id that is not an
    # object, and update_ref refused a ref string where it wanted an oid.
    root, run = fresh_repo
    _run("attest", "heads/main", "--repo", str(root), "--signer", "op", "--claim", "{}", "--json")
    assert _json_out(capsys)["run_id"] == run
    _run("promote", "heads/main", "--repo", str(root), "--name", "prod", "--json")
    assert _json_out(capsys)["run_id"] == run
    assert Repo.open(root).read_ref("promotions/prod") == run


def test_every_write_verb_also_accepts_a_bare_run_oid(fresh_repo, capsys):
    root, run = fresh_repo
    _run("attest", run, "--repo", str(root), "--signer", "op", "--claim", "{}", "--json")
    assert _json_out(capsys)["run_id"] == run
    _run("evaluate", run, "--repo", str(root), "--evaluator", "j", "--score", "q=1", "--json")
    assert _json_out(capsys)["run_id"] == run
    _run("promote", run, "--repo", str(root), "--name", "gate", "--json")
    assert _json_out(capsys)["run_id"] == run


# --- cross-version write gate ------------------------------------------------


def test_all_three_verbs_append_to_every_released_repository_and_it_fscks(golden_repo, capsys):
    repo_arg = str(golden_repo)
    run = Repo.open(golden_repo).read_ref("heads/main")

    _run(
        "attest",
        "heads/main",
        "--repo",
        repo_arg,
        "--signer",
        "release-manager",
        "--claim",
        '{"kind": "approval", "note": "cross-version gate"}',
        "--json",
    )
    attestation = _json_out(capsys)["attestation_id"]

    _run(
        "evaluate",
        "heads/main",
        "--repo",
        repo_arg,
        "--evaluator",
        "gate-judge",
        "--score",
        "quality=1.0",
        "--json",
    )
    evaluation = _json_out(capsys)["attestation_id"]

    _run("promote", "heads/main", "--repo", repo_arg, "--name", "released", "--json")
    promotion = _json_out(capsys)

    repo = Repo.open(golden_repo)
    assert repo.has(attestation) and repo.has(evaluation)
    assert repo.read_ref("promotions/released") == run == promotion["run_id"]

    result = repo.fsck(deep=True)
    assert result.ok, result.errors
    # The appended objects are reachable and typed, so they are counted, not ignored.
    assert attestation in set(repo.iter_oids()) and evaluation in set(repo.iter_oids())


def test_the_appended_score_is_readable_back_over_every_released_repository(golden_repo, capsys):
    """First cross-version coverage of the evaluation-score read path."""
    repo_arg = str(golden_repo)
    run = Repo.open(golden_repo).read_ref("heads/main")
    _run(
        "evaluate",
        "heads/main",
        "--repo",
        repo_arg,
        "--evaluator",
        "gate-judge",
        "--score",
        "quality=1.0",
        "--json",
    )
    evaluation = _json_out(capsys)["attestation_id"]

    # (a) repo-search's own attestation scan, over a repository an older release wrote.
    _run("repo-search", "--repo", repo_arg, "--json", "--min-score", "1.0")
    rows = {row["run_id"]: row for row in _json_out(capsys)["results"]}
    assert rows[run]["score"] == 1.0

    # (b) the reverse association lookup semantic_diff's summary uses.
    summary = Repo.open(golden_repo).diff(run, run).summary["evaluations"]["left"]
    assert {"attestation": evaluation, "scores": {"quality": 1.0}} in summary


def test_the_committed_fixtures_are_never_mutated(golden_repo, capsys):
    """The copy is what gets written; the tracked repository must stay byte-identical."""
    version = golden_repo.name
    source = COMPAT / version / "repo"
    before = {
        path.relative_to(source): path.read_bytes() for path in source.rglob("*") if path.is_file()
    }
    _run("attest", "heads/main", "--repo", str(golden_repo), "--signer", "x", "--claim", "{}")
    capsys.readouterr()
    after = {
        path.relative_to(source): path.read_bytes() for path in source.rglob("*") if path.is_file()
    }
    assert before == after


# --- MCP parity: one object, one evaluation claim shape ----------------------


def test_cli_attest_writes_the_byte_identical_object_the_mcp_tool_writes(fresh_repo, capsys):
    root, run = fresh_repo
    claim = {"kind": "approval", "note": "ship it"}
    mcp = FakeMCP()
    register_repository_tools(mcp, str(root))
    expected = mcp.tools["attest_run"](run, claim, "release-manager")["attestation_id"]

    _run(
        "attest",
        "heads/main",
        "--repo",
        str(root),
        "--signer",
        "release-manager",
        "--claim",
        json.dumps(claim),
        "--json",
    )
    # Content addressing: equal oids is equal stored bytes, by construction.
    assert _json_out(capsys)["attestation_id"] == expected


def test_cli_evaluate_writes_the_byte_identical_object_evaluate_run_writes(fresh_repo, capsys):
    root, run = fresh_repo
    mcp = FakeMCP()
    register_repository_tools(mcp, str(root))
    expected = mcp.tools["evaluate_run"](run, {"quality": 0.5, "safety": 1.0}, "judge")
    _run(
        "evaluate",
        "heads/main",
        "--repo",
        str(root),
        "--evaluator",
        "judge",
        "--score",
        "quality=0.5",
        "--score",
        "safety=1.0",
        "--json",
    )
    assert _json_out(capsys)["attestation_id"] == expected["attestation_id"]


def test_there_is_exactly_one_evaluation_claim_shape(fresh_repo, capsys):
    """``evaluate`` must be ``attest`` with the claim readers already understand."""
    root, run = fresh_repo
    _run("evaluate", "heads/main", "--repo", str(root), "--evaluator", "j", "--score", "q=0.25")
    capsys.readouterr()
    _run(
        "attest",
        "heads/main",
        "--repo",
        str(root),
        "--signer",
        "j",
        "--claim",
        '{"kind": "evaluation", "scores": {"q": 0.25}}',
        "--json",
    )
    hand_written = _json_out(capsys)["attestation_id"]
    payload = Repo.open(root).get(hand_written).payload()
    assert payload["claim"] == {"kind": "evaluation", "scores": {"q": 0.25}}
    assert payload["signer"] == "j" and payload["target_id"] == run
    # Both routes converge on the same object, so no second shape can exist.
    assert Repo.open(root).diff(run, run).summary["evaluations"]["left"] == [
        {"attestation": hand_written, "scores": {"q": 0.25}}
    ]


def test_evidence_ids_are_linked_and_default_to_the_mcp_empty_list(fresh_repo, capsys):
    root, run = fresh_repo
    repo = Repo.open(root)
    event = repo.get(run).payload()["events"][0]
    _run(
        "attest",
        "heads/main",
        "--repo",
        str(root),
        "--signer",
        "op",
        "--claim",
        "{}",
        "--evidence",
        event,
        "--json",
    )
    emitted = _json_out(capsys)
    assert emitted["evidence_ids"] == [event]
    assert Repo.open(root).get(emitted["attestation_id"]).payload()["evidence_ids"] == [event]


def test_a_claim_file_and_an_inline_claim_are_the_same_object(fresh_repo, tmp_path, capsys):
    root, _ = fresh_repo
    claim = '{"kind": "approval", "reviewers": ["a", "b"]}'
    path = tmp_path / "claim.json"
    path.write_text(claim, encoding="utf-8")
    _run("attest", "heads/main", "--repo", str(root), "--signer", "op", "--claim", claim, "--json")
    inline = _json_out(capsys)["attestation_id"]
    _run(
        "attest",
        "heads/main",
        "--repo",
        str(root),
        "--signer",
        "op",
        "--claim-file",
        str(path),
        "--json",
    )
    assert _json_out(capsys)["attestation_id"] == inline


# --- promotion CAS -----------------------------------------------------------


def test_promote_defaults_to_expect_absent_and_refuses_to_clobber(fresh_repo, capsys):
    root, run = fresh_repo
    _run("promote", "heads/main", "--repo", str(root), "--name", "prod", "--json")
    assert _json_out(capsys)["created"] is True

    repo = Repo.open(root)
    other = repo.fork(run, repo.get(run).payload()["events"][0], ref="experiments/next")
    message = _refused(capsys, "promote", other, "--repo", str(root), "--name", "prod")
    assert "--expected-old" in message and run in message
    # The refusal is total: the release gate still points where it did.
    assert Repo.open(root).read_ref("promotions/prod") == run


def test_expected_old_is_the_only_way_to_move_a_promotion(fresh_repo, capsys):
    root, run = fresh_repo
    _run("promote", "heads/main", "--repo", str(root), "--name", "prod")
    capsys.readouterr()
    repo = Repo.open(root)
    other = repo.fork(run, repo.get(run).payload()["events"][0], ref="experiments/next")

    # A stale expected value is refused just as an absent one is, and says so.
    stale = _refused(
        capsys, "promote", other, "--repo", str(root), "--name", "prod", "--expected-old", other
    )
    assert "--expected-old" in stale and run in stale

    _run("promote", other, "--repo", str(root), "--name", "prod", "--expected-old", run, "--json")
    emitted = _json_out(capsys)
    assert emitted["created"] is False and emitted["expected_old"] == run
    assert Repo.open(root).read_ref("promotions/prod") == other


def test_promote_has_no_force_flag_and_never_may(fresh_repo):
    """A release gate has no override. This test exists to keep it that way."""
    import argparse

    parser = argparse.ArgumentParser()
    add_repo_parsers(parser.add_subparsers(dest="command"))
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            promote = action.choices["promote"]
            break
    options = {name for entry in promote._actions for name in entry.option_strings}
    assert "--force" not in options and "-f" not in options
    assert options >= {"--name", "--expected-old", "--repo", "--json"}
    # Belt and braces: the flag must not exist under any spelling, in the parser
    # that declares it or in the module that would have to read it back.
    written = Path(cli.__file__).with_name("_repo_cli_write.py").read_text(encoding="utf-8")
    declared = Path(cli.__file__).with_name("_repo_cli_parser.py").read_text(encoding="utf-8")
    assert '"--force"' not in declared and "args.force" not in written


# --- refusals ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("claim", "fragment"),
    [
        ("{oops", "must be valid JSON"),
        ('["a", "list"]', "must be a JSON object"),
        ('"a string"', "must be a JSON object"),
        ("7", "must be a JSON object"),
        ("null", "must be a JSON object"),
    ],
)
def test_attest_refuses_a_claim_that_is_not_a_json_object(fresh_repo, capsys, claim, fragment):
    root, _ = fresh_repo
    message = _refused(
        capsys, "attest", "heads/main", "--repo", str(root), "--signer", "op", "--claim", claim
    )
    assert fragment in message
    # Nothing was written: refusing at the door is the point.
    assert not [oid for oid in Repo.open(root).iter_oids() if oid.startswith("attestation:")]


@pytest.mark.parametrize("verb", WRITE_VERBS)
def test_every_verb_refuses_a_ref_that_names_no_run(fresh_repo, capsys, verb):
    root, _ = fresh_repo
    extra = {
        "attest": ("--signer", "op", "--claim", "{}"),
        "evaluate": ("--evaluator", "j", "--score", "q=1"),
        "promote": ("--name", "prod"),
    }[verb]
    message = _refused(capsys, verb, "heads/nope", "--repo", str(root), *extra)
    assert "cannot resolve heads/nope" in message


@pytest.mark.parametrize("verb", WRITE_VERBS)
def test_every_verb_refuses_an_oid_no_object_backs(fresh_repo, capsys, verb):
    root, _ = fresh_repo
    ghost = "run:sha256:" + "0" * 64
    extra = {
        "attest": ("--signer", "op", "--claim", "{}"),
        "evaluate": ("--evaluator", "j", "--score", "q=1"),
        "promote": ("--name", "prod"),
    }[verb]
    message = _refused(capsys, verb, ghost, "--repo", str(root), *extra)
    assert "cannot resolve" in message


@pytest.mark.parametrize("verb", WRITE_VERBS)
def test_every_verb_refuses_a_target_that_is_not_a_run(fresh_repo, capsys, verb):
    root, run = fresh_repo
    event = Repo.open(root).get(run).payload()["events"][0]
    extra = {
        "attest": ("--signer", "op", "--claim", "{}"),
        "evaluate": ("--evaluator", "j", "--score", "q=1"),
        "promote": ("--name", "prod"),
    }[verb]
    message = _refused(capsys, verb, event, "--repo", str(root), *extra)
    assert "not a run object" in message


@pytest.mark.parametrize("score", ["q", "q=", "=1", "q=abc", "q=nan", "q=inf"])
def test_evaluate_refuses_a_score_that_is_not_a_finite_number(fresh_repo, capsys, score):
    root, _ = fresh_repo
    message = _refused(
        capsys, "evaluate", "heads/main", "--repo", str(root), "--evaluator", "j", "--score", score
    )
    assert "--score" in message


def test_evaluate_refuses_the_same_score_name_twice(fresh_repo, capsys):
    root, _ = fresh_repo
    message = _refused(
        capsys,
        "evaluate",
        "heads/main",
        "--repo",
        str(root),
        "--evaluator",
        "j",
        "--score",
        "q=1",
        "--score",
        "q=0",
    )
    assert "given twice" in message


def test_claim_and_claim_file_are_mutually_exclusive_and_one_is_required(fresh_repo):
    root, _ = fresh_repo
    for args in (
        ["attest", "heads/main", "--repo", str(root), "--signer", "op"],
        [
            "attest",
            "heads/main",
            "--repo",
            str(root),
            "--signer",
            "op",
            "--claim",
            "{}",
            "--claim-file",
            "x.json",
        ],
    ):
        with pytest.raises(SystemExit) as exited:
            cli.main(args)
        # argparse owns 2 for a usage error; the verb itself never emits it.
        assert exited.value.code == 2


# --- the human surface -------------------------------------------------------


def test_human_output_says_the_signer_label_is_self_asserted(fresh_repo, capsys):
    root, _ = fresh_repo
    _run("attest", "heads/main", "--repo", str(root), "--signer", "op", "--claim", "{}")
    out = capsys.readouterr().out
    assert "unsigned" in out and "self-asserted" in out
    _run("evaluate", "heads/main", "--repo", str(root), "--evaluator", "j", "--score", "q=1")
    out = capsys.readouterr().out
    assert "unsigned" in out and "self-asserted" in out


def test_there_is_no_signature_flag_to_forge_one_with(fresh_repo):
    """v3 ships no attestation signing helper; a ``--sign`` flag would be a lie."""
    import argparse

    parser = argparse.ArgumentParser()
    add_repo_parsers(parser.add_subparsers(dest="command"))
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            attest = action.choices["attest"]
            break
    options = {name for entry in attest._actions for name in entry.option_strings}
    assert not options & {"--sign", "--signature", "--key", "--sign-with"}


def test_recorded_content_cannot_forge_markup_in_a_write_receipt(fresh_repo, capsys):
    root, _ = fresh_repo
    hostile = "[/bold]\x1b]52;c;pwn\x1b\\ \x9b31m"
    _run("attest", "heads/main", "--repo", str(root), "--signer", hostile, "--claim", "{}")
    out = capsys.readouterr().out
    assert not {"\x1b", "\x9b", "\x00"} & set(out)
