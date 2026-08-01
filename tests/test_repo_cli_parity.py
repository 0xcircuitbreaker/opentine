"""The CLI <-> MCP parity gate: one repository engine, two surfaces.

Phase 5 of the Surface Release finishes the v3 command line, so from here on the
question is no longer "does the CLI expose this?" but "do the two surfaces still
agree?". Every v3 capability is reachable two ways — an operator types a verb, a
model calls an MCP tool — and both land on the same ``Repo`` methods. Two failure
modes follow, and this module fails CI on either:

  * **Drift.** A tool gains a capability the CLI never grows (or the reverse), so
    an operator cannot reproduce what an agent did, or an agent cannot be audited
    by hand. ``TOOL_TO_VERB`` is a *total* bijection between the v3 MCP tools and
    their CLI verbs; the CLI-only administrative verbs are enumerated explicitly
    rather than waved through, so adding a tool or a verb without its twin is red.
  * **Accidental convergence.** The surfaces differ on purpose in four places,
    every one of them a trust decision — the operator at the terminal already
    holds the repository, while a model over MCP is acting on run content it read
    *out of* that repository. Each divergence is asserted here as a fact, so
    "fixing" one by making the surfaces match also turns this file red and forces
    the security argument to be re-made rather than quietly discarded.

Everything runs in-process: the MCP side through the ``FakeMCP`` harness, the CLI
side through ``opentine.cli.main`` and the real argparse tree. No subprocess.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from opentine import cli
from opentine._cli_parser import _build_parser
from opentine.kernel import KernelError
from opentine.mcp_repository import register_repository_tools
from opentine.repo_cli import REPO_COMMANDS
from opentine.repository import Repo
from opentine.trace import Recorder, TraceEvent
from tests.test_mcp_repository import FakeMCP

#: Every v3 MCP tool and the CLI verb that reaches the same engine. Both columns
#: are closed sets: the left one is what ``register_repository_tools`` registers
#: with ``allow_promotion=True``, the right one is a subset of ``REPO_COMMANDS``.
#: The ``repo-`` prefix appears only where a legacy v2 verb owns the plain name
#: (``show``, ``search``, ``diff``, ``fork``, ``resume``); ``context``,
#: ``attest``, ``evaluate``, and ``promote`` have no legacy namesake and stay bare.
TOOL_TO_VERB = {
    "attest_run": "attest",
    "context_slice": "context",
    "evaluate_run": "evaluate",
    "fork_run_v3": "repo-fork",
    "inspect_object": "object",
    "promote_run": "promote",
    "resume_run_v3": "repo-resume",
    "search_runs": "repo-search",
    "semantic_diff": "repo-diff",
}

#: v3 verbs with no MCP tool, and why. Two categories, neither of which is a
#: reasoning step an agent takes mid-run.
#:
#: *Administration and transport* — ``init``, ``fsck``, ``pack``, ``migrate-v3``,
#: ``fetch``, ``push``, ``clone`` — create a store, verify it, or move bytes
#: between stores. Each hands out a capability (filesystem paths, network
#: endpoints, credentials) that has no business being driven by run content.
#:
#: *Human rendering* — ``repo-show`` and ``repo-log`` — draw a run's step tree and
#: its event ancestry for a terminal. A model reads the same objects through
#: ``inspect_object`` and ``context_slice``; a rendered tree would only cost it
#: tokens. These two are why "every MCP tool has a CLI verb" is not symmetric.
#:
#: Listing them keeps "the CLI has a verb MCP lacks" from being a silent,
#: growing category: a new one must be added here, with a reason.
CLI_ONLY_VERBS = {
    "clone",
    "fetch",
    "fsck",
    "init",
    "migrate-v3",
    "pack",
    "push",
    "repo-log",
    "repo-show",
}

#: The one prefix that predates the naming rule. ``repo-log`` shipped in 0.3.0 and
#: ``log`` was never a legacy verb, so by today's rule it would be plain ``log``.
#: Renaming a shipped verb is a breaking change, so it is grandfathered here
#: rather than quietly dropped from the rule — a *second* entry needs an argument.
GRANDFATHERED_PREFIX = {"repo-log"}


def _parser_choices() -> set[str]:
    parser = _build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    raise AssertionError("tine parser has no subcommands")


def _subparser(name: str) -> argparse.ArgumentParser:
    parser = _build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices[name]
    raise AssertionError("tine parser has no subcommands")


def parity_errors(tools: set[str], verbs: set[str]) -> list[str]:
    """Both directions of the map, as messages. Empty means the surfaces agree.

    Factored out so the drift test below can feed it a *simulated* change and
    prove the gate actually bites, rather than trusting that it would.
    """
    errors = []
    for tool in sorted(tools - set(TOOL_TO_VERB)):
        errors.append(f"MCP tool {tool!r} has no CLI verb in TOOL_TO_VERB")
    for tool in sorted(set(TOOL_TO_VERB) - tools):
        errors.append(f"TOOL_TO_VERB maps {tool!r}, which MCP no longer registers")
    for tool, verb in sorted(TOOL_TO_VERB.items()):
        if verb not in verbs:
            errors.append(f"CLI verb {verb!r} (twin of {tool!r}) is not routed")
    for verb in sorted(verbs - set(TOOL_TO_VERB.values()) - CLI_ONLY_VERBS):
        errors.append(f"CLI verb {verb!r} has no MCP tool and is not declared CLI-only")
    return errors


@pytest.fixture
def repo_with_run(tmp_path: Path) -> tuple[Path, str, str]:
    """A repository, the run oid ``heads/main`` names, and one event oid in it."""
    root = tmp_path / "repo"
    repo = Repo.init(root)
    recorder = Recorder.start(repo, capture=False)
    event = recorder.append(TraceEvent("model", 1, "trace", "span", outputs={"text": "hi"}))
    run = recorder.finalize()
    repo.update_ref("heads/main", run, expected_old=repo.read_ref("heads/main"))
    return root, run, event


def _mcp(root: Path, *, allow_promotion: bool = True) -> FakeMCP:
    mcp = FakeMCP()
    register_repository_tools(mcp, str(root), allow_promotion=allow_promotion)
    return mcp


# --- totality ----------------------------------------------------------------


def test_every_mcp_tool_has_a_cli_verb_and_every_v3_verb_is_accounted_for(repo_with_run):
    root, _, _ = repo_with_run
    # allow_promotion=True enumerates the *maximal* tool set, so the map is checked
    # against every tool that can exist, not just the default-on ones.
    errors = parity_errors(set(_mcp(root).tools), set(REPO_COMMANDS))
    assert errors == [], "\n".join(errors)


def test_the_mapped_verbs_are_exactly_the_routed_v3_surface(repo_with_run):
    root, _, _ = repo_with_run
    assert set(_mcp(root).tools) == set(TOOL_TO_VERB)
    assert set(TOOL_TO_VERB.values()) | CLI_ONLY_VERBS == set(REPO_COMMANDS)
    # The parser and the dispatch table are already pinned to each other by
    # tests/test_repo_cli_routing.py; this asserts the map reaches real verbs.
    assert set(TOOL_TO_VERB.values()) <= _parser_choices()


def test_the_map_is_a_bijection_so_no_two_tools_claim_one_verb():
    assert len(set(TOOL_TO_VERB.values())) == len(TOOL_TO_VERB)
    assert not set(TOOL_TO_VERB.values()) & CLI_ONLY_VERBS


def test_the_repo_prefix_is_used_only_where_a_legacy_verb_owns_the_name():
    """The naming rule, asserted rather than only documented.

    ``repo-`` is a collision marker, not a namespace: it appears exactly where a
    v2 verb already owns the plain name (``show``, ``search``, ``diff``, ``fork``,
    ``resume``), which is why ``context``, ``attest``, ``evaluate``, and
    ``promote`` are bare. ``repo-log`` is the single grandfathered exception.
    """
    legacy = set(cli.LEGACY_COMMANDS)
    for verb in set(TOOL_TO_VERB.values()) | CLI_ONLY_VERBS:
        if verb in GRANDFATHERED_PREFIX:
            continue
        plain = verb.removeprefix("repo-")
        if verb.startswith("repo-"):
            assert plain in legacy, f"{verb} is prefixed but {plain!r} is not a legacy verb"
        else:
            assert verb not in legacy, f"{verb} collides with a legacy verb and needs the prefix"
    # And the grandfathered one really is the only prefix without a collision.
    assert GRANDFATHERED_PREFIX == {
        verb
        for verb in set(TOOL_TO_VERB.values()) | CLI_ONLY_VERBS
        if verb.startswith("repo-") and verb.removeprefix("repo-") not in legacy
    }


# --- drift detection: the gate must actually bite ----------------------------


def test_a_new_mcp_tool_without_a_cli_verb_fails_the_gate(repo_with_run):
    root, _, _ = repo_with_run
    mcp = _mcp(root)

    @mcp.tool()
    def rewrite_history() -> None:  # a tool nobody added a verb for
        """Simulated drift."""

    errors = parity_errors(set(mcp.tools), set(REPO_COMMANDS))
    assert errors == ["MCP tool 'rewrite_history' has no CLI verb in TOOL_TO_VERB"]


def test_a_removed_cli_verb_fails_the_gate(repo_with_run):
    root, _, _ = repo_with_run
    verbs = set(REPO_COMMANDS) - {"repo-fork"}
    assert parity_errors(set(_mcp(root).tools), verbs) == [
        "CLI verb 'repo-fork' (twin of 'fork_run_v3') is not routed"
    ]


def test_an_undeclared_cli_only_verb_fails_the_gate(repo_with_run):
    root, _, _ = repo_with_run
    verbs = set(REPO_COMMANDS) | {"repo-rebase"}
    assert parity_errors(set(_mcp(root).tools), verbs) == [
        "CLI verb 'repo-rebase' has no MCP tool and is not declared CLI-only"
    ]


# --- pinned divergence 1: promotion is operator-default, model-opt-in ---------


def test_promote_is_unconditional_on_the_cli_and_gated_on_mcp(repo_with_run):
    """DELIBERATE DIVERGENCE. Making these agree is a security regression.

    A promotion ref is a release gate, and the run content an MCP client reads is
    untrusted, so text recorded inside a run can ask a model to promote a run of
    the attacker's choosing. The operator at the terminal already holds the
    repository and needs no such gate.
    """
    root, _, _ = repo_with_run
    assert "promote_run" not in _mcp(root, allow_promotion=False).tools
    assert "promote_run" in _mcp(root, allow_promotion=True).tools
    # No flag, no environment variable, no config: the CLI verb is always there.
    assert "promote" in REPO_COMMANDS and "promote" in _parser_choices()


# --- pinned divergence 2: the writable namespace -----------------------------


def test_mcp_forks_are_confined_to_experiments_and_cli_forks_are_not(repo_with_run, capsys):
    """DELIBERATE DIVERGENCE. The confinement's threat model is model input.

    A fork's ref update is an unconditional overwrite, so any ref an MCP client
    may write is a ref a model can destroy — and it is choosing that ref from
    content it read out of the repository. The CLI's caller is the operator.
    """
    root, run, event = repo_with_run
    tools = _mcp(root).tools

    with pytest.raises(ValueError, match="experiments/"):
        tools["fork_run_v3"](run, event, "heads/main")
    with pytest.raises(ValueError, match="experiments/"):
        tools["resume_run_v3"](run, "heads/main")

    # The same two operations, from the CLI, onto a non-experiments ref: allowed.
    cli.main(["repo-fork", run, "--repo", str(root), "--from-event", event, "--ref", "heads/side"])
    cli.main(["repo-resume", run, "--repo", str(root), "--ref", "tags/checkpoint"])
    capsys.readouterr()
    repo = Repo.open(root)
    assert repo.read_ref("heads/side") and repo.read_ref("tags/checkpoint")
    assert repo.fsck(deep=True).ok


@pytest.mark.parametrize("verb", ["repo-fork", "repo-resume"])
def test_ref_is_required_with_no_default_on_both_lineage_verbs(verb):
    """The CLI's substitute for the namespace confinement: state the destination.

    Unconfined *and* defaulted would mean a bare ``tine repo-fork RUN`` advancing
    whatever ref the default named. Required-with-no-default makes every fork
    destination an explicit operator choice.
    """
    actions = {
        option: entry for entry in _subparser(verb)._actions for option in entry.option_strings
    }
    ref = actions["--ref"]
    assert ref.required is True and ref.default is None
    with pytest.raises(SystemExit) as exited:
        cli.main([verb, "run:sha256:" + "0" * 64, "--repo", "."])
    assert exited.value.code == 2  # argparse usage error, not a repository refusal


# --- pinned divergence 3: --json is a documented superset ---------------------


def test_cli_json_receipts_are_a_strict_superset_of_the_mcp_return(repo_with_run, capsys):
    """DELIBERATE DIVERGENCE. The MCP return is a model's working set.

    ``fork_run_v3`` returns ``{ref, run_id}`` — what the model needs to keep
    going. The CLI receipt also records what the operator typed and what it
    resolved to, because it is an audit artifact a script may archive. Superset,
    never a different spelling: the shared keys must carry the same values.
    """
    root, run, event = repo_with_run
    forked = _mcp(root).tools["fork_run_v3"](run, event, "experiments/parity")
    cli.main(
        [
            "repo-fork",
            "heads/main",
            "--repo",
            str(root),
            "--from-event",
            event,
            "--ref",
            "experiments/parity",
            "--json",
        ]
    )
    receipt = json.loads(capsys.readouterr().out)
    assert set(receipt) > set(forked), "the CLI receipt must be a strict superset"
    # Content addressing: an identical run oid is identical stored bytes, so the
    # two surfaces provably wrote one object rather than two similar ones.
    assert {key: receipt[key] for key in forked} == forked
    assert set(receipt) - set(forked) == {
        "command",
        "from_event",
        "overrides",
        "repo",
        "resumed",
        "source_run_id",
        "target",
    }


def test_the_resume_receipt_is_a_superset_too(repo_with_run, capsys):
    root, run, _ = repo_with_run
    resumed = _mcp(root).tools["resume_run_v3"](run, "experiments/parity")
    cli.main(
        ["repo-resume", "heads/main", "--repo", str(root), "--ref", "experiments/parity", "--json"]
    )
    receipt = json.loads(capsys.readouterr().out)
    assert set(receipt) > set(resumed)
    assert {key: receipt[key] for key in resumed} == resumed


# --- pinned divergence 4: the CLI is stricter about scores -------------------


def test_cli_evaluate_refuses_non_finite_scores_that_mcp_passes_straight_through(
    repo_with_run, capsys
):
    """DELIBERATE DIVERGENCE, and the one that runs the *other* way.

    ``repo-search`` averages evaluation scores, so a nan or inf would poison every
    average it reached. The CLI parses ``--score NAME=VALUE`` out of a shell
    string, so it owns that door and closes it *before* any engine call, naming
    the flag the operator typed.

    ``evaluate_run`` takes an already-typed ``dict[str, float]`` and adds no check
    of its own: the value travels all the way into ``canonical_json``, which
    refuses it as a ``KernelError`` about JSON encoding. Nothing is stored either
    way — the divergence is *where* and *how legibly* the refusal happens, and the
    CLI is strictly the stricter surface. Recorded, not fixed: adding a check at
    the MCP boundary is a change to the tool's contract, and the kernel is
    already the authority that nothing non-finite is ever written.
    """
    root, run, _ = repo_with_run
    with pytest.raises(KernelError, match="NaN"):
        _mcp(root).tools["evaluate_run"](run, {"quality": float("nan")}, "judge")
    assert not [oid for oid in Repo.open(root).iter_oids() if oid.startswith("attestation:")], (
        "the kernel is the backstop: nothing non-finite is ever stored"
    )

    for score in ("quality=nan", "quality=inf", "quality=-inf"):
        with pytest.raises(SystemExit) as exited:
            cli.main(
                ["evaluate", run, "--repo", str(root), "--evaluator", "judge", "--score", score]
            )
        assert exited.value.code == 1
        captured = capsys.readouterr()
        assert captured.out.strip() == ""
        # The operator gets the flag they typed, not a canonical-JSON error.
        assert "--score quality must be finite" in captured.err
        assert "canonical JSON" not in captured.err
