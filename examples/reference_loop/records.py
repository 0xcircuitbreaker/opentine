"""What one iteration records before any gate: the run, spend, evals, monitors, integrity.

* the **mutation run** (an ordinary captured run: one model step with its cost,
  then each tool call the optimizer made);
* its **spend** on the signed budget ledger and the **containment** policy it
  ran under (signed by the runner key);
* **monitor verdicts**: a rule monitor scores every tool call; a verdict that is
  not ``allow`` is signed by the monitor key and held (advisory mode, D12);
* signed **evals** (eval key): visible items, the sealed holdout (unsealed for
  this run, which writes a held access record) and the canary set;
* the **integrity check** against the signed protected list, with the advisory
  detectors over the run record; a ``fail:`` files a signed, held taint.
"""

from __future__ import annotations

import json
from typing import Any

from reference_loop import toy
from reference_loop.tine import must, tine
from reference_loop.world import MONITOR, SANDBOX, SUBJECT, World


def _key(world: World, name: str) -> Any:
    from opentine._signing_keys import ed25519_private_from_file

    return ed25519_private_from_file(world.keys[name], signer=False)


def put_run(world: World, step: int, proposal: Any, model: str) -> str:
    from opentine.core import Run, RunStatus, StepKind
    from opentine.repository import Repo

    run = Run(id=f"reference-loop-step-{step}", model_info=model,
              user_prompt=f"step {step}: {proposal.note}")  # fmt: skip
    run.add_step(StepKind.model, {"text": f"propose a variant: {proposal.note}"},
                 {"text": proposal.note}, cost=proposal.cost,
                 usage={"input": proposal.tokens - 50, "output": 50})  # fmt: skip
    for call in proposal.tool_calls:
        run.add_step(StepKind.tool, call, {"text": "ok"})
    run.status = RunStatus.completed
    return Repo.open(world.root).put_run(run).run_id


def spend_and_contain(world: World, run: str) -> None:
    """The run's recorded cost as a signed, held ``spend`` entry; its sandbox policy."""
    from opentine import _budget_ledger, _containment
    from opentine._cost_export import aggregate
    from opentine.repository import Repo

    repo = Repo.open(world.root)
    world.clock.tick()
    fields = {"run": run, "cost": aggregate(repo.load_run(run)), "gpu_hours": 0.0,
              "egress_bytes": 0}  # fmt: skip
    _budget_ledger.append(repo, SUBJECT, "spend", fields, _key(world, "runner"),
                          at_ms=world.clock.ms())  # fmt: skip
    _containment.record(repo, run, SANDBOX, _key(world, "runner"))


def monitor(world: World, run: str, calls: list[dict[str, Any]], at: str) -> list[str]:
    """Score each tool call; sign and hold every verdict that is not ``allow``."""
    from opentine import _monitor_verdict as mv
    from opentine._monitors import RuleMonitor
    from opentine.repository import Repo

    rules = RuleMonitor(MONITOR["id"], MONITOR["rules"])
    flagged = []
    for call in calls:
        reply = rules.score({"tool": call["name"], "arguments": call["arguments"]})
        if reply["score"] < 0.5:
            continue
        digest = mv.input_digest("tools/call", call)
        claim = {"convention": mv.CONVENTION, "monitor": rules.identity, "input_digest": digest,
                 "reasoning": {"state": "unavailable", "digest": None}, "tool": call["name"],
                 "session": run.rsplit(":", 1)[-1][:16], "score": float(reply["score"]),
                 "threshold": 0.5, "action": reply.get("action", "flag"), "enforced": False,
                 "mode": "advisory", "decided_by": "monitor", "latency_ms": 0,
                 "deadline_ms": 1000, "fail_closed": False,
                 "trajectories": [{"role": "original", "digest": digest}], "chosen": "original",
                 "stop": None, "decided_at": at}  # fmt: skip
        flagged.append(mv.record(Repo.open(world.root), run, claim, _key(world, "monitor")))
    return flagged


def evaluate(world: World, run: str, solver: str, kind: str, tasks: list[dict]) -> dict[str, Any]:
    from opentine._eval_run import run_eval
    from opentine._eval_scorers import parse

    folder = world.path("evals", run.rsplit(":", 1)[-1][:16], kind)
    got = toy.run_solver(world.path("sandbox", run.rsplit(":", 1)[-1][:16]), solver, tasks)
    outputs = {t["id"]: {"output": got.get(t["id"], ""), "run": run} for t in tasks}
    summary = run_eval(tasks, parse("exact"), _key(world, "eval"), folder, outputs=outputs,
                       created_at=world.clock.tick(), threshold=1.0)  # fmt: skip
    passed = {t["id"] for t in tasks if outputs[t["id"]]["output"] == t["expected"]}
    return {"dir": folder.as_posix(), "rate": summary["passed"] / summary["items"],
            "passed": passed}  # fmt: skip


def unseal(world: World, run: str) -> list[dict[str, Any]]:
    """The holdout items, released for *run* under a signed, held access record."""
    out = world.path("released", f"{run.rsplit(':', 1)[-1][:16]}.jsonl")
    must("dataset", "unseal", world.files["holdout"], "--out", out.as_posix(), "--run", run,
         "--why", "candidate eval", "--purpose", "eval", "--key", world.keys["eval"],
         "--seal-key", world.files["seal_key"], "--repo", world.repo, "--at",
         world.clock.tick(), "--json")  # fmt: skip
    keep = ("id", "input", "expected")
    rows = [json.loads(line) for line in out.read_bytes().decode("utf-8").splitlines() if line]
    out.unlink()  # used in memory only; nothing a later variant could find on disk
    return [{k: r[k] for k in keep} for r in rows]


def integrity(world: World, run: str, proposal: Any, scores: dict[str, float]) -> dict[str, Any]:
    tests = "".join(f"assert solve({i['input']!r}) == {i['expected']!r}\n"
                    for i in toy.items("visible"))  # fmt: skip
    diff = [{"path": c["arguments"]["file_path"], "status": "modified",
             "added": c["arguments"]["content"].splitlines(), "removed": []}
            for c in proposal.tool_calls if c["name"] == "write"]  # fmt: skip
    events = [{"tool": c["name"], "input": c["arguments"], "output": {"text": "ok"}}
              for c in proposal.tool_calls]  # fmt: skip
    record = {"id": run, "diff": diff, "test_sources": {"tests/test_visible.py": tests},
              "events": events, "claimed_tool_calls": events, "scores": scores}  # fmt: skip
    path = world.path("integrity", f"{run.rsplit(':', 1)[-1][:16]}.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(record, sort_keys=True).encode("utf-8"))
    code, body = tine("integrity", "check", run, "--record", path.as_posix(), "--key",
                      world.keys["runner"], "--at", world.clock.tick(), "--repo", world.repo,
                      "--json")  # fmt: skip
    findings = body.get("findings", [])
    fail = sorted({f["code"] for f in findings if f["level"] == "fail"})
    if code != 0 and not fail:  # the check did not run (missing list, bad record): fail closed
        fail = ["fail:integrity-check-did-not-run"]
    return {
        "ok": code == 0,
        "tainted": bool(body.get("taint")),
        "fail": fail,
        "advisory": sorted({f["code"] for f in findings if f["level"] == "advisory"}),
    }


__all__ = ["evaluate", "integrity", "monitor", "put_run", "spend_and_contain", "unseal"]
