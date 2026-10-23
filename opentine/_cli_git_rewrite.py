"""``tine rebase`` and ``tine cherry-pick``: history-preserving run rewrites.

Nothing is rewritten in place -- objects are content-addressed and immutable.

* ``tine rebase RUN --onto-model M [--from-step N]`` forks RUN after its first
  N steps (default 1) with the model overridden to M, onto
  ``experiments/rebase/<id>`` unless ``--ref`` names another ref. The new run is
  ``running``: it is the staged base an agent resumes on the new model (the same
  object ``repo-fork --model`` writes). Its ``forked_from`` names RUN, so ``tine
  log --graph`` shows it beside the original.
* ``tine cherry-pick RUN:STEP --onto RUN2`` copies one recorded step -- its
  inputs, outputs, usage and cost, by blob reference -- onto the end of RUN2 as
  a new event whose parent is RUN2's tip, in a new run forked from RUN2 (onto
  ``experiments/cherry-pick/<id>`` unless ``--ref``). RUN2 itself is untouched.

STEP is a 1-based step number or an ``event:sha256:`` id.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine import _hooks
from opentine._cli_common import _terminal
from opentine._cli_json import emit
from opentine._repo_cli_render import _short_oid
from opentine._repo_cli_write import _run_oid
from opentine.repo import Repo
from opentine.repository._fork_state import fork_payload
from opentine.repository._refs import normalize_ref

EVENT_COPY_FIELDS = (
    "billing",
    "cost",
    "duration",
    "error",
    "input_blob",
    "kind",
    "model",
    "output_blob",
    "time_unix",
    "tool",
    "usage",
    "provider",
)


def _events(repo: Repo, run_id: str) -> list[str]:
    return list(repo.get(run_id).payload().get("events") or [])


def _step(events: list[str], step: str) -> str:
    if step.startswith("event:"):
        if step not in events:
            raise ValueError(f"{step} is not an event of that run")
        return step
    try:
        index = int(step)
    except ValueError:
        raise ValueError(f"step must be a 1-based number or an event id, got {step!r}") from None
    if not 1 <= index <= len(events):
        raise ValueError(f"step {index} is out of range (the run has {len(events)} steps)")
    return events[index - 1]


def _place(repo: Repo, ref: str | None, space: str, run_id: str) -> str:
    name = normalize_ref(ref or f"experiments/{space}/{run_id.split(':')[-1][:12]}")
    repo.update_ref(name, run_id, expected_old=repo.read_ref(name), actor=space)
    return name


def cmd_rebase(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    source = _run_oid(repo, args.run)
    keep = _step(_events(repo, source), str(args.from_step))
    _hooks.require(repo.path, "pre-record", {"OPENTINE_SOURCE": source})
    overrides: dict[str, Any] = {"model": args.onto_model, "resume": True}
    if args.prompt is not None:
        overrides["prompt"] = args.prompt
    new = repo.fork(source, keep, overrides=overrides)
    ref = _place(repo, args.ref, "rebase", new)
    _hooks.run_hook(repo.path, "post-run", {"OPENTINE_RUN": new, "OPENTINE_REF": ref})
    if getattr(args, "json", False):
        emit({"command": "rebase", "source": source, "run_id": new, "ref": ref})
        return
    console.print(
        f"Rebased {_short_oid(source)} onto model {_terminal(args.onto_model)}: "
        f"{_terminal(ref)} -> {_short_oid(new)} (running; resume it on the new model)"
    )


def cmd_cherry_pick(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    if ":event:" in args.pick:
        run_part, event_part = args.pick.split(":event:", 1)
        step = "event:" + event_part
    else:
        run_part, _, step = args.pick.rpartition(":")
        if not run_part or not step.isdigit():
            raise ValueError("cherry-pick takes RUN:STEP (a 1-based step number or an event id)")
    source = _run_oid(repo, run_part)
    event = _step(_events(repo, source), step)
    onto = _run_oid(repo, args.onto)
    onto_payload = repo.get(onto).payload()
    tips = list(onto_payload.get("tips") or onto_payload.get("events") or [])
    if not tips:
        raise ValueError(f"{args.onto} has no events to build on")
    _hooks.require(repo.path, "pre-record", {"OPENTINE_SOURCE": source})
    picked = repo.get(event).payload()
    copy = {name: picked[name] for name in EVENT_COPY_FIELDS if name in picked}
    copy.update(parent_ids=[tips[-1]], causal_ids=[])
    copy.setdefault("legacy_step_id", picked.get("legacy_step_id", ""))
    new_event = repo.put("event", copy)
    run = fork_payload(repo, onto, onto_payload, tips[-1], None)
    run["events"] = [*run["events"], new_event]
    run["tips"] = [new_event]
    new = repo.put("run", run)
    ref = _place(repo, args.ref, "cherry-pick", new)
    _hooks.run_hook(repo.path, "post-run", {"OPENTINE_RUN": new, "OPENTINE_REF": ref})
    if getattr(args, "json", False):
        emit({"command": "cherry-pick", "event": event, "onto": onto, "run_id": new, "ref": ref})
        return
    console.print(
        f"Picked {_short_oid(event)} onto {_short_oid(onto)}: {_terminal(ref)} -> {_short_oid(new)}"
    )


__all__ = ["cmd_cherry_pick", "cmd_rebase"]
