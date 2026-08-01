"""``tine replay --verify``: prove a replay reproduces the run it replays.

"Deterministic replay" was an asserted property; this makes it a check with an
exit status, so CI can gate on it.

**The check is not a tautology.** ``Run.fork`` deep-copies steps in memory, so
diffing a fork against the run it came from always passes and proves nothing
about what a replay *writes*. The verdict is therefore built from two
derivations that meet only through the filesystem: (1) load the source, derive
the cached replay, ``save()`` it to a **temporary** path and ``Run.load`` it
back — the artifact a real replay would have left, read as a stranger reads it;
(2) load the *source bytes* again into a fresh object and derive the replay a
second time. Reproduced means both derivations mint the same 64-hex id, the
reloaded artifact's canonical digest verifies, the retained slice is exactly
``retained_closure`` (the helper ``--inspect`` previews and ``Run.fork``
retains), and the diff between the reloaded artifact and the second derivation
carries no structural drift. A serializer that dropped a step, a fork id that
depended on load order, or a digest that did not survive the round trip all
fail here; an in-memory diff would notice none of them.

With ``--harness`` the same shape is the real nondeterminism gate: the harness
is executed **twice** over one context, each run saved to its own temporary path
and read back, and the two artifacts compared. Two executions must mint two
*distinct* 64-hex ids (a rerun is a new act, never a name derived from the
source id) and agree on every structural field.

Drift is classified over the buckets ``_graph_diff`` already reports:
``_drift``'s cost/usage/billing deltas are *accounting*, everything ``_fields``
adds is *structural*. ``--ignore-cost-drift`` downgrades an accounting-only
difference to a pass; structural drift always fails. Exit status is binary: 0
reproduced, 1 drift or a source that would not load (argparse owns 2). An
unloadable source yields no verdict, so it is a human message and never a JSON
object — see ``_cli_json_flow``.

``--verify`` writes nothing under ``.tine_runs/`` unless ``--save`` is given;
the temporary workspace is removed on every path, failures included. ``--save``
copies the verified bytes out, still refusing to overwrite without ``--force``.
The status a cached replay carries is the CLI's, documented on ``cmd_replay``.
"""

from __future__ import annotations

import argparse
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opentine._cli_common import (
    _find_run,
    _harness_from_args,
    _resolve_step_ref,
    _run_context,
    _terminal,
    console,
)
from opentine._cli_flow import _require_output_slot
from opentine._cli_json_flow import emit_replay_verify
from opentine._cli_render import print_replay_verify
from opentine._graph_analysis import retained_closure
from opentine._graph_diff import diff_runs
from opentine.core import Run, short_id
from opentine.harnesses import OpentineHarness

#: Exactly the deltas ``_graph_diff._drift`` reports; everything ``_fields`` adds
#: on top is structural. A guard test pins the split against that function.
ACCOUNTING_FIELDS = frozenset({"billing", "cost", "usage"})
_HEX64 = re.compile(r"[0-9a-f]{64}")


def expected_slice(run: Run, from_step: str | None) -> tuple[str, set[str]]:
    """(fork point, the step ids a replay from it retains) — one answer, three readers."""
    fork_point = _resolve_step_ref(run, from_step)
    return fork_point, retained_closure(run, fork_point)


def cache_replay(run: Run, fork_point: str) -> Run:
    """The artifact a cached replay produces, spelled once so ``--verify`` cannot
    check something other than what ``cmd_replay`` writes.

    A cached replay only reuses recorded steps, so it is an idempotent act:
    nonce="" keeps the id reproducible, which is what makes a second replay
    resolve to the same path and hit the overwrite refusal (pinned by
    test_cached_replay_never_derives_an_output_path_from_untrusted_run_id).
    """
    replayed = run.fork(fork_point, intent={"replay": "cache"}, nonce="")
    replayed.metadata["replay"] = {
        "mode": "cache",
        "reused_steps": len(replayed.steps),
        "source_run": run.id,
    }
    replayed.status = run.status
    return replayed


def classify_drift(diff: Any) -> tuple[list[str], list[str]]:
    """Split one ``RunDiff`` into (structural, accounting) labels."""
    structural: list[str] = []
    accounting: list[str] = []
    for change in diff.changed:
        label = short_id(change.step_a.id)
        for delta in change.fields:
            bucket = accounting if delta.name in ACCOUNTING_FIELDS else structural
            bucket.append(f"{label} {delta.name}")
    structural.extend(f"{short_id(step.id)} missing" for step in diff.only_a)
    structural.extend(f"{short_id(step.id)} added" for step in diff.only_b)
    return sorted(structural), sorted(accounting)


@dataclass
class Verdict:
    """One completed comparison; the human text and the JSON both render this."""

    mode: str
    path: str
    run_id: str
    replay_id: str
    second_id: str
    identity_ok: bool
    integrity: Any
    structural: list[str] = field(default_factory=list)
    accounting: list[str] = field(default_factory=list)
    ignore_cost_drift: bool = False
    fork_point: str | None = None
    expected_steps: int | None = None
    reused_steps: int | None = None
    slice_ok: bool | None = None

    @property
    def reproduced(self) -> bool:
        drift = self.structural or (self.accounting and not self.ignore_cost_drift)
        return all((self.identity_ok, self.integrity.ok, self.slice_ok is not False, not drift))


def _cache_verdict(run: Run, path: Path, args: argparse.Namespace, room: Path) -> Verdict:
    fork_point, expected = expected_slice(run, args.from_step)
    artifact = room / "replay.tine"
    # Round trip: the replay leaves the process as bytes and comes back a stranger.
    cache_replay(run, fork_point).save(artifact)
    reloaded, integrity = Run.load(artifact), Run.verify_integrity(artifact)
    # The second derivation starts from the source *bytes*, not from `run`: a fork
    # id that depended on the loaded object's history would diverge right here.
    again = Run.load(path)
    second_point, second_expected = expected_slice(again, args.from_step)
    second = cache_replay(again, second_point)
    structural, accounting = classify_drift(diff_runs(second, reloaded))
    # The expected closure, the two derivations, and the round-tripped file: one set.
    slices = (second_expected, set(reloaded.graph.steps), set(second.graph.steps))
    return Verdict(
        mode="cache",
        path=str(path),
        run_id=run.id,
        replay_id=reloaded.id,
        second_id=second.id,
        identity_ok=reloaded.id == second.id and bool(_HEX64.fullmatch(second.id)),
        integrity=integrity,
        structural=structural,
        accounting=accounting,
        ignore_cost_drift=bool(getattr(args, "ignore_cost_drift", False)),
        fork_point=fork_point,
        expected_steps=len(expected),
        reused_steps=len(reloaded.steps),
        slice_ok=all(item == expected for item in slices),
    )


def _execute(args: argparse.Namespace, task: str, context: dict, destination: Path) -> Run:
    wrapper = OpentineHarness(_harness_from_args(args))
    try:
        return wrapper.run_sync(task, context=context, save_path=destination)
    except Exception as exc:
        console.print(f"[red]Harness replay failed:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc


def _harness_verdict(run: Run, path: Path, args: argparse.Namespace, room: Path) -> Verdict:
    task = args.prompt or run.user_prompt
    if not task:
        console.print("[red]--prompt is required when replaying a harness run.[/]")
        raise SystemExit(1)
    start = _resolve_step_ref(run, args.from_step) if args.from_step is not None else None
    context = _run_context(run, start)
    artifact = room / "rerun-a.tine"
    _execute(args, task, context, artifact)
    reloaded, integrity = Run.load(artifact), Run.verify_integrity(artifact)
    second = _execute(args, task, context, room / "rerun-b.tine")
    structural, accounting = classify_drift(diff_runs(second, reloaded))
    return Verdict(
        mode="rerun",
        path=str(path),
        run_id=run.id,
        replay_id=reloaded.id,
        second_id=second.id,
        # A rerun is a new act: two executions must mint two *distinct* digest ids,
        # never a name derived from the source run id.
        identity_ok=reloaded.id != second.id
        and all(bool(_HEX64.fullmatch(value)) for value in (reloaded.id, second.id)),
        integrity=integrity,
        structural=structural,
        accounting=accounting,
        ignore_cost_drift=bool(getattr(args, "ignore_cost_drift", False)),
    )


def verify_replay(args: argparse.Namespace) -> None:
    """Run the check and exit 0 (reproduced) or 1 (drift, or an unloadable source)."""
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {_terminal(args.run_id)}[/]")
        raise SystemExit(1)
    output = Path(args.save) if args.save else None
    if output is not None:
        _require_output_slot(output, getattr(args, "force", False))
    if args.mode == "rerun" and not args.harness:
        console.print(
            "[red]Rerun replay requires an explicit --harness or opentine-native Agent API.[/]"
        )
        raise SystemExit(1)
    try:
        run = Run.load(path)
    # No replay exists, so there is no verdict: a human message, never JSON.
    except (OSError, RecursionError, ValueError) as exc:
        console.print(f"[red]Cannot verify {_terminal(path)}:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    room = Path(tempfile.mkdtemp(prefix="tine-verify-"))
    try:
        derive = _harness_verdict if args.harness else _cache_verdict
        verdict = derive(run, path, args, room)
        if output is not None:
            # The bytes that were verified, not a second serialization of them.
            shutil.copyfile(room / ("rerun-a.tine" if args.harness else "replay.tine"), output)
    except (KeyError, ValueError) as exc:
        console.print(f"[red]{_terminal(exc)}[/]")
        raise SystemExit(1) from exc
    finally:
        # Success, drift, and exception alike: the workspace never outlives the check.
        shutil.rmtree(room, ignore_errors=True)
    if getattr(args, "json", False):
        emit_replay_verify(verdict)
    else:
        print_replay_verify(verdict)
    if not verdict.reproduced:
        raise SystemExit(1)
