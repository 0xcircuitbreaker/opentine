"""One iteration of the loop: propose, record, judge, and promote only through the gates.

Order matters. Everything about the candidate is recorded first (run, spend,
containment, monitor verdicts, evals, integrity). Then people decide
(oversight k-of-n), the policy key signs an admission decision over the shipped
``promote`` policy, and ``tine promote --require-admission promote`` moves the
label only when that admission, the statistical test on visible and held-out
evals, the approvals, the budget cap, the sealed holdout's exposure budget and
the integrity taints all agree. A promoted variant then faces the canary; a
significant regression reverts the label. Last, the variant is signed into the
lineage with its evals and decision, and its uplift records are held.
"""

from __future__ import annotations

from typing import Any

from reference_loop import records, toy
from reference_loop.tine import must, tine
from reference_loop.world import LABEL, LOOP, SANDBOX, SUBJECT, World


def _short(run: str) -> str:
    return run.rsplit(":", 1)[-1][:16]


def _state(world: World) -> str:
    return world.path("promotion", "state").as_posix()


def oversight(world: World, run: str, clean: bool) -> dict[str, Any]:
    """Simulated people: two approvers sign a clean candidate; one rejects a flagged one.

    The optimizer also tries to approve every candidate; the CLI refuses it
    (``oversight.key-separation``), and the outcome is reported.
    """
    item = f"promotion:{LABEL}:{run}"
    common = ["--state", _state(world), "--repo", world.repo, "--json"]
    self_code, _ = tine("oversight", "approve", item, "--key", world.keys["optimizer"],
                        "--at", world.clock.tick(), *common)  # fmt: skip
    approvals = []
    if not clean:
        must("oversight", "reject", item, "--key", world.keys["a1"], "--note",
             "integrity or monitor findings", "--at", world.clock.tick(), *common)  # fmt: skip
        return {"decision": "reject", "approvals": [], "optimizer_refused": self_code != 0}
    for name in ("a1", "a2"):
        must("oversight", "approve", item, "--key", world.keys[name], "--at", world.clock.tick(),
             *common)  # fmt: skip
        out = world.path("approvals", f"{_short(run)}-{name}.json").as_posix()
        must(
            "promote",
            run,
            "--baseline",
            LABEL,
            "--approve",
            "--key",
            world.keys[name],
            "--out",
            out,
            "--state",
            _state(world),
            "--at",
            world.clock.tick(),
            "--json",
        )
        approvals.append(out)
    return {"decision": "approve", "approvals": approvals, "optimizer_refused": self_code != 0}


def admit(world: World, run: str, evals: list[str]) -> dict[str, Any]:
    """``tine policy check promote``, signed by the policy key; failed rules by id."""
    from opentine import _containment

    params = [f"sandbox_digest={_containment.digest(SANDBOX)}", f"label={LABEL}"]
    argv = ["policy", "check", "promote", "--subject", run, "--key", world.keys["policy"],
            "--holdout", world.files["holdout"], "--budget", SUBJECT, "--at", world.clock.tick(),
            "--repo", world.repo, "--json"]  # fmt: skip
    argv += [a for p in params for a in ("--param", p)]
    argv += [a for e in evals for a in ("--evals", e)]
    _code, body = tine(*argv)
    failed = sorted(r["id"] for r in body.get("rules", [])
                    if r.get("effect") == "require" and r.get("outcome") != "true")  # fmt: skip
    return {"decision": body.get("decision", "error"), "failed": failed, "params": params}


def promote(world: World, run: str, cand: dict, base: dict, approvals: list[str],
            spent: str, admitted: dict) -> dict[str, Any]:  # fmt: skip
    out = world.path("promotion", "decisions", _short(run))
    argv = ["promote", run, "--baseline", LABEL, "--key", world.keys["promoter"], "--policy",
            world.files["promote"], "--policy-attestation", world.files["promote_sig"],
            "--baseline-evals", base["visible"]["dir"], "--evals", cand["visible"]["dir"],
            "--holdout", base["holdout"]["dir"], cand["holdout"]["dir"], "--spent", spent,
            "--sealed-holdout", world.files["holdout"], "--require-admission", "promote",
            "--admission-holdout", world.files["holdout"], "--admission-budget", SUBJECT,
            "--state", _state(world), "--out", out.as_posix(), "--at", world.clock.tick(),
            "--repo", world.repo, "--json"]  # fmt: skip
    argv += [a for p in admitted["params"] for a in ("--admission-param", p)]
    argv += [a for e in (cand["visible"]["dir"], cand["holdout"]["dir"])
             for a in ("--admission-evals", e)]  # fmt: skip
    argv += [a for f in approvals for a in ("--approval", f)]
    code, body = tine(*argv)
    refusals = [r["code"] for r in body.get("refusals", [])]
    decision = (out / "decision.json").as_posix() if code == 0 else None
    return {"promoted": code == 0, "refusals": refusals, "decision": decision}


def canary(world: World, run: str, cand: dict, base: dict) -> dict[str, Any]:
    out = world.path("promotion", "canary", _short(run))
    code, body = tine("promote", run, "--baseline", LABEL, "--key", world.keys["promoter"],
                      "--policy", world.files["promote"], "--canary", cand["canary"]["dir"],
                      "--baseline-evals", base["canary"]["dir"], "--state", _state(world),
                      "--out", out.as_posix(), "--at", world.clock.tick(), "--json")  # fmt: skip
    return {"action": body.get("action", "error"), "code": code,
            "refusals": [r["code"] for r in body.get("refusals", [])]}  # fmt: skip


def revert(world: World, run: str, reason: str) -> dict[str, Any]:
    """Take the label back from *run* (used when the canary could not decide)."""
    out = world.path("promotion", "reverts", _short(run))
    body = must("promote", run, "--baseline", LABEL, "--key", world.keys["promoter"], "--policy",
                world.files["promote"], "--revert", "--reason", reason, "--state", _state(world),
                "--out", out.as_posix(), "--at", world.clock.tick(), "--json")  # fmt: skip
    return {"action": body.get("action", "revert"), "code": 0, "refusals": [], "reason": reason}


def lineage(world: World, run: str, solver: str, parent: str | None, cand: dict,
            decision: str | None, selector: str) -> str:  # fmt: skip
    argv = ["lineage", "record", "--run", run, "--key", world.keys["runner"], "--code-tree",
            toy.digest(solver), "--selector", selector, "--loop", LOOP, "--at",
            world.clock.tick(), "--repo", world.repo, "--json"]  # fmt: skip
    argv += ["--eval", cand["visible"]["dir"], "--eval", cand["holdout"]["dir"]]
    argv += ["--parent", parent] if parent else []
    argv += ["--decision", decision] if decision else []
    return must(*argv)["variant"]


def uplift(world: World, run: str, variant: str, generation: int, holdout: dict) -> int:
    """One held uplift record per operation: did this generation solve it on the holdout?"""
    tasks = toy.items("holdout", world.item_seed())
    for op in toy.ORDER:
        ids = {t["id"] for t in tasks if t["input"].startswith(op + ":")}
        ok = "yes" if ids <= holdout["passed"] else "no"
        must("uplift", "record", "--suite", world.files["suite"], "--type", "run", "--task", op,
             "--subject", "reference-loop", "--condition", "ai", "--success", ok,
             "--generation", str(generation), "--run", run, "--key", world.keys["eval"],
             "--at", world.clock.tick(), "--repo", world.repo, "--json")  # fmt: skip
    return len(toy.ORDER)


def evaluate_all(world: World, run: str, solver: str) -> dict[str, dict]:
    canary = toy.items("canary", world.item_seed())
    return {
        "visible": records.evaluate(world, run, solver, "visible", toy.items("visible")),
        "holdout": records.evaluate(world, run, solver, "holdout", records.unseal(world, run)),
        "canary": records.evaluate(world, run, solver, "canary", canary),
    }


__all__ = ["admit", "canary", "evaluate_all", "lineage", "oversight", "promote", "revert", "uplift"]
