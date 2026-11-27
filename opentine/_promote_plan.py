"""``tine promote --plan``: the pre-registered, selection-adjusted test (0.86).

:func:`check` runs after the 0.58 gate and adds these refusals:

``promote.plan-missing``      the policy requires a plan (``require_plan``; on under
                              ``profile = "rsi"``) and none was given;
``promote.plan-invalid``      the plan or reveal does not verify or is malformed;
``promote.plan-signer``       the plan is not signed by an eval signer of the policy
                              (under the rsi profile: a pinned ``scorer`` key);
``promote.plan-mismatch``     the plan names another dataset, epochs or cluster key, or
                              the candidate eval was not run under this plan
                              (``coverage.json`` binds the plan's digest);
``promote.plan-after-outputs`` the plan was signed after the candidate's verdicts;
``promote.seed-not-committed`` no reveal, one that does not open the commitment, or
                              one signed before the candidate's verdicts;
``promote.coverage``          no signed coverage, or scored/planned below the floor;
``promote.candidates-over-plan`` the lineage records more sibling candidates than the
                              plan's ``max_candidates``, or the plan has already
                              promoted that many (Holm never steps past ``m``);
``promote.lineage-missing``  a lineage is recorded but not the candidate (or, under the
                              rsi profile, the candidate has no lineage record at all);
``promote.uncorrected``       the planned test fails at the corrected alpha;
``promote.eval-signer-role``  (rsi profile) a verdict signer holds no pinned ``scorer``
                              role in the owner trust bundle, or is an optimizer key.

Without a plan and without ``require_plan`` the promotion reports
``advisory:promote.no-plan`` and does not block (owner decision D12).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from opentine._promote_checks import refusal


def _time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _rows(folder: Path) -> list[dict[str, Any]]:
    from opentine._eval_run import read_verdicts

    try:
        return [r for r in read_verdicts(folder) if isinstance(r, dict)]
    except (OSError, ValueError):
        return []


def roles(store: Path | None, folders: dict[str, Path]) -> list[dict[str, str]]:
    """Every verdict signer must be a pinned ``scorer`` key that is not an optimizer key."""
    from opentine._key_roles_pin import granting

    keys, why = granting(store, "scorer")
    out = []
    for side, folder in folders.items():
        unpinned = {r.get("signer") for r in _rows(folder)} - keys
        if unpinned:
            out.append(refusal("promote.eval-signer-role", f"{side} eval: {why}"))
    return out


def siblings(lineage: Path | None, candidate: str) -> int | None:
    """Recorded variants sharing the candidate's parent set; ``None`` when nothing is
    recorded, ``0`` when variants are recorded but not the candidate."""
    from opentine import _lineage

    if lineage is None or not (Path(lineage) / "variants").is_dir():
        return None
    claims = []
    for name, raw in _lineage.read_folder(lineage).items():
        if not name.startswith("variants/"):
            continue
        try:
            doc = _lineage.loads(raw)
        except (ValueError, RecursionError):
            continue
        claim = doc.get("claim") if isinstance(doc, dict) else None
        if isinstance(claim, dict) and isinstance(claim.get("parents"), list) and (
                _lineage.signed(doc)):  # fmt: skip
            claims.append(claim)
    mine = [c for c in claims if c.get("mutation_run") == candidate]
    if not mine:
        return 0 if claims else None
    parents = sorted(map(str, mine[0]["parents"]))
    return len({c.get("variant") for c in claims if sorted(map(str, c["parents"])) == parents})


def _plan(plan_path: Path, reveal_path: Path | None, out: list) -> tuple[dict, int, str] | None:
    from opentine import _eval_plan as plans

    try:
        plan = plans.opened_plan(plans.load(plan_path))
        if reveal_path is None:
            raise plans.PlanError("promote.seed-not-committed", "no reveal (--reveal) was given")
        doc = plans.load(reveal_path)
        return plan, plans.opened_reveal(doc, plan), doc["signature"]["signed_at"]
    except plans.PlanError as exc:
        out.append(refusal(exc.code, str(exc)))
    except (OSError, ValueError, RecursionError) as exc:
        out.append(refusal("promote.plan-invalid", f"the plan or reveal cannot be read: {exc}"))
    return None


def _coverage(plan: dict, claim: dict, base: dict | None, out: list) -> None:
    from decimal import Decimal

    if claim["plan_sha256"] != plan["sha256"]:
        why = "the candidate eval was not run under the plan"
        out.append(refusal("promote.plan-mismatch", why))
    want = (plan["claim"]["epochs"], plan["claim"]["cluster_key"])
    for side, found in (("candidate", claim), ("baseline", base)):
        got = (found["epochs"], found["cluster_key"]) if found else (1, None)
        if got[0] != want[0] or (side == "candidate" and got[1] != want[1]):
            why = f"{side} eval epochs/cluster key {got} differ from the plan"
            out.append(refusal("promote.plan-mismatch", why))
    floor = Decimal(plan["claim"]["min_coverage"])
    planned, scored = claim["planned"], claim["scored"]
    if not planned or Decimal(scored) / Decimal(planned) < floor:
        out.append(refusal("promote.coverage", f"scored {scored} of {planned} planned "
                           f"(skipped {len(claim['skipped'])}, errored {len(claim['errored'])}) "
                           f"< floor {floor}"))  # fmt: skip


def check(policy: dict[str, Any], *, candidate: str, history: list[dict[str, Any]],
          baseline: Path, evals: Path, plan_path: Path | None, reveal_path: Path | None,
          lineage: Path | None, store: Path | None,
          folders: dict[str, Path]) -> tuple[list, list, dict | None]:  # fmt: skip
    """``(refusals, advisories, evidence)``; evidence is signed into the decision."""
    from opentine import _eval_coverage as coverage
    from opentine._eval_reduce import analyse, corrected_alpha

    out = roles(store, folders) if policy.get("require_signer_roles") else []
    if plan_path is None:
        if policy.get("require_plan"):
            return out + [refusal("promote.plan-missing", "the policy requires --plan")], [], None
        return (
            out,
            [
                {
                    "code": "advisory:promote.no-plan",
                    "detail": "no pre-registered plan (--plan): the test is uncorrected",
                }
            ],
            None,
        )
    opened = _plan(Path(plan_path), reveal_path, out)
    if opened is None:
        return out, [], None
    plan, seed, revealed_at = opened
    claim = plan["claim"]
    if policy.get("require_signer_roles"):
        from opentine._key_roles_pin import granting

        allowed = granting(store, "scorer")[0]
    else:
        allowed = set(policy["eval_signers"])
    if plan["signer"] not in allowed:
        out.append(refusal("promote.plan-signer", "the plan's signer may not sign evals"))
    rows_b, rows_c = _rows(baseline), _rows(evals)
    if {r.get("dataset") for r in rows_c} != {claim["dataset"]}:
        out.append(refusal("promote.plan-mismatch", "the candidate scored another dataset"))
    stamps = [_time(r["created_at"]) for r in rows_c if isinstance(r.get("created_at"), str)]
    if not stamps or _time(plan["signed_at"]) > min(stamps):
        out.append(refusal("promote.plan-after-outputs",
                           "the plan was signed after the candidate's verdicts"))  # fmt: skip
    if not stamps or _time(revealed_at) < max(stamps):
        out.append(refusal("promote.seed-not-committed",
                           "the seed was revealed before the candidate's verdicts"))  # fmt: skip
    cov_c = coverage.read(evals, {r.get("signer") for r in rows_c})
    cov_b = coverage.read(baseline, {r.get("signer") for r in rows_b})
    if cov_c is None:
        out.append(refusal("promote.coverage", "the candidate eval has no signed coverage.json"))
    else:
        _coverage(plan, cov_c, cov_b, out)
    found = siblings(lineage, candidate)
    if found is not None and found > claim["max_candidates"]:
        out.append(refusal("promote.candidates-over-plan", f"the lineage records {found} "
                           f"candidates; the plan allows {claim['max_candidates']}"))  # fmt: skip
    if found == 0 or (found is None and policy.get("require_lineage")):
        out.append(refusal("promote.lineage-missing", "the lineage does not record the candidate"))
    m = max(claim["max_candidates"], found or 0)
    done = [h for h in history if h.get("action") == "promote"]
    rank = 1 + sum(1 for h in done if h.get("plan_sha256") == plan["sha256"])
    if rank > m:
        out.append(refusal("promote.candidates-over-plan", f"the plan already promoted {rank - 1} "
                           f"of its {m} candidates"))  # fmt: skip
    alpha = corrected_alpha(claim["alpha"], claim["correction"], m, rank)
    if out:
        return out, [], None
    row = analyse(rows_b, rows_c, claim, seed=seed, alpha=alpha, clusters=cov_c["clusters"])
    if not row["passed"]:
        out.append(refusal("promote.uncorrected", f"{claim['metric']} delta {row['delta']} "
                           f"fails {claim['test']} at {claim['correction']}-corrected alpha "
                           f"{alpha} (m={m}, step {rank})"
                           + ("" if row["resolved"] else "; too few resamples")))  # fmt: skip
    evidence = {"plan_sha256": plan["sha256"], "plan_signer": plan["signer"], "seed": seed,
                "candidates": m, "lineage_candidates": found, "step": rank,
                "correction": claim["correction"], "alpha": claim["alpha"],
                "corrected_alpha": alpha, "analysis": row,
                "coverage": {k: cov_c[k] for k in ("planned", "scored", "skipped",
                                                   "errored")}}  # fmt: skip
    return out, [], evidence


def planned(policy: dict[str, Any], record: dict[str, Any], candidate: str, baseline: Path,
            evals: Path, holdout: tuple[Path, Path] | None, plan: Path | None,
            reveal: Path | None, lineage: Path | None,
            repo_path: Path | None) -> tuple[list, list, dict | None]:  # fmt: skip
    """:func:`check` with the repository's defaults: ``.tine`` store and lineage folder."""
    store = Path(repo_path) / ".tine" if repo_path is not None else None
    if lineage is None and repo_path is not None:
        lineage = Path(repo_path) / ".tine" / "lineage"
    folders = {"baseline": baseline, "candidate": evals,
               **({"holdout baseline": holdout[0], "holdout candidate": holdout[1]}
                  if holdout else {})}  # fmt: skip
    return check(policy, candidate=candidate, history=record["history"],
                 baseline=baseline, evals=evals, plan_path=plan, reveal_path=reveal,
                 lineage=lineage, store=store, folders=folders)  # fmt: skip


__all__ = ["check", "planned", "roles", "siblings"]
