"""Drive the reference loop: seed, iterate, then read back what the records say.

:func:`run_loop` returns a report (also written to ``WORK/report.json``) with
one row per step and a final section computed only from the signed records:
the capability trend over lineage generations (``tine trends``), the uplift
time horizon (``tine uplift horizon``), the curated training set with the
taint filter applied (``tine dataset curate``), every variant's lineage check
and the holdout's exposure.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reference_loop import records, step, toy
from reference_loop import world as W
from reference_loop.models import Proposal, StubModel
from reference_loop.tine import TineError, isolated, must, tine


def _spent(world: W.World) -> str:
    """The ledger's total; an unreadable ledger stops the loop rather than reading as $0."""
    body = must("budget", "status", W.SUBJECT, "--at", world.clock.tick(), "--repo",
                       world.repo, "--json")  # fmt: skip
    used = ((body.get("status") or {}).get("totals") or {}).get("money_usd")
    if isinstance(used, bool) or not isinstance(used, (int, float, str)):
        raise TineError(f"budget status gave no spend total: {body}")
    return str(used)


def seed(world: W.World) -> dict[str, Any]:
    """The root variant: a solver that knows no operation."""
    text = toy.source([])
    calls = [{"name": "write", "arguments": {"file_path": "solver.py", "content": text}}]
    run = records.put_run(world, 0, Proposal(text, [], calls, "import the toy solver"), "import")
    records.spend_and_contain(world, run)
    W.uplift_suite(world, run)
    evals = step.evaluate_all(world, run, text)
    variant = step.lineage(world, run, text, None, evals, None, "seed")
    step.uplift(world, run, variant, 0, evals["holdout"])
    return {"run": run, "variant": variant, "source": text, "ops": [], "evals": evals,
            "generation": 0}  # fmt: skip


def _may_act(world: W.World, stop_at: int | None, i: int) -> bool:
    """The oversight side signs a continue proof (or, at *stop_at*, a fleet stop); the loop
    then checks it before acting. Under the stop policy a loop with no fresh proof halts."""
    channel = ["--channel", world.files["stop_channel"], "--fleet", W.LOOP, "--key",
               world.keys["policy"], "--repo", world.repo, "--at", world.clock.tick()]  # fmt: skip
    if stop_at is not None and i >= stop_at:
        tine("stop", "issue", *channel, "--reason", f"stopped at step {i}")
    else:
        tine("stop", "continue", *channel, "--run", W.LOOP)
    code, _ = tine("stop", "status", "--run", W.LOOP, "--repo", world.repo, "--at",
                   world.clock.tick(), "--json")  # fmt: skip
    return code == 0


def iterate(world: W.World, model: Any, i: int, champ: dict, seen: set[str],
            stop_at: int | None = None) -> dict[str, Any]:  # fmt: skip
    if not _may_act(world, stop_at, i):  # check-before-act: a stop or a stale proof halts
        return {"step": i, "stopped": "fleet-stop"}
    code, _ = tine("budget", "check", W.SUBJECT, "--key", world.keys["runner"], "--at",
                   world.clock.tick(), "--repo", world.repo, "--json")  # fmt: skip
    if code != 0:
        return {"step": i, "stopped": "budget"}
    visible = toy.items("visible")
    if isinstance(model, StubModel):
        prop = model.propose(i, champ["ops"], visible)
    else:
        prop = model.propose(i, champ["ops"], visible, current=champ["source"])
    if prop.source in seen:
        return {"step": i, "stopped": "no-new-variant"}
    seen.add(prop.source)
    run = records.put_run(world, i, prop, getattr(model, "name", "model"))
    records.spend_and_contain(world, run)
    flags = records.monitor(world, run, prop.tool_calls, world.clock.tick())
    evals = step.evaluate_all(world, run, prop.source)
    scores = {"visible": evals["visible"]["rate"], "holdout": evals["holdout"]["rate"]}
    integ = records.integrity(world, run, prop, scores)
    # special-casing is advisory (D12) for the gates; the simulated people still read it
    hacky = "advisory:special-casing" in integ.get("advisory", [])
    people = step.oversight(world, run, clean=not integ["fail"] and not flags and not hacky)
    admitted = step.admit(world, run, [evals["visible"]["dir"], evals["holdout"]["dir"]])
    spent = _spent(world)
    moved = step.promote(world, run, evals, champ["evals"], people["approvals"], spent,
                         admitted)  # fmt: skip
    canary = step.canary(world, run, evals, champ["evals"]) if moved["promoted"] else None
    if canary is not None and canary["action"] not in ("canary", "revert"):
        canary = step.revert(world, run, "canary-did-not-run")  # a missing check never keeps
    variant = step.lineage(world, run, prop.source, champ["variant"], evals, moved["decision"],
                           f"{getattr(model, 'name', 'model')}: {prop.note}")  # fmt: skip
    generation = champ["generation"] + 1
    # every variant's uplift is recorded, failed or tainted ones too: dropping them would
    # make the trend look better than the loop is
    uplifts = step.uplift(world, run, variant, generation, evals["holdout"])
    kept = moved["promoted"] and canary is not None and canary["action"] != "revert"
    row = {"step": i, "run": run, "variant": variant, "parent": champ["variant"],
           "seeded": prop.seeded, "note": prop.note, "scores": scores,
           "monitor_flags": len(flags), "integrity": integ, "oversight": people["decision"],
           "optimizer_approval_refused": people["optimizer_refused"],
           "admission": {k: admitted[k] for k in ("decision", "failed")},
           "promote": {k: moved[k] for k in ("promoted", "refusals")},
           "canary": canary["action"] if canary else None, "kept": kept,
           "uplift_records": uplifts, "spent_usd": spent}  # fmt: skip
    if kept:
        champ.update(run=run, variant=variant, source=prop.source, ops=prop.ops, evals=evals,
                     generation=generation)  # fmt: skip
    return row


def finale(world: W.World, variants: list[str]) -> dict[str, Any]:
    repo = ["--repo", world.repo, "--json"]
    _c, trends = tine("trends", "--loop", W.LOOP, "--resamples", "200", *repo)
    _c, horizon = tine("uplift", "horizon", "--suite", world.files["suite"], "--resamples",
                       "200", *repo)  # fmt: skip
    _c, curated = tine(
        "dataset",
        "curate",
        "--select",
        "all",
        "--out",
        "loop-trajectories",
        "--key",
        world.keys["curator"],
        "--at",
        world.clock.tick(),
        *repo,
    )
    _c, exposure = tine("dataset", "exposure", world.files["holdout"], *repo)
    checks = {v: tine("lineage", "check", v, *repo)[0] for v in variants}
    from opentine.repository import Repo

    fsck = Repo.open(world.root).fsck().ok  # every stored object re-hashes, offline
    return {"trends": trends, "horizon": horizon, "curated": curated, "exposure": exposure,
            "lineage_check_exit": checks, "fsck_ok": fsck}  # fmt: skip


def run_loop(work: Path, *, steps: int = 8, model: Any = None, cap_usd: float = 10.0,
             hack_at: int | None = 2, regress_at: int | None = 4,
             stop_at: int | None = None) -> dict[str, Any]:  # fmt: skip
    model = model or StubModel(hack_at=hack_at, regress_at=regress_at)
    world = W.build(Path(work))
    with isolated(world.path("config"), world.owner_vkey):
        W.configure(world, cap_usd=cap_usd, max_unseals=steps + 2)
        champ = seed(world)
        seen = {champ["source"]}
        rows: list[dict[str, Any]] = []
        for i in range(1, steps + 1):
            rows.append(iterate(world, model, i, champ, seen, stop_at))
            if "stopped" in rows[-1]:
                break
        variants = [r["variant"] for r in rows if "variant" in r]
        report = {"steps": rows, "champion": {k: champ[k] for k in ("run", "variant", "ops")},
                  "final": finale(world, variants), "roles": W.roles(world),
                  "owner_vkey": world.owner_vkey}  # fmt: skip
    data = json.dumps(report, indent=2, sort_keys=True, default=sorted) + "\n"
    with open(world.path("report.json"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(data)
    return report


__all__ = ["finale", "iterate", "run_loop", "seed"]
