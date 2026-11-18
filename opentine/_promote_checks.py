"""The promotion gate's checks: every refusal a named reason (0.58).

:func:`gate` reads the promotion policy, the signed eval folders, the signed
approvals and the declared spend, and returns ``(evidence, refusals)``. A
refusal is ``{"code": "promote.*", "detail": ...}``; ``tine promote`` moves
the label only when there is none. Codes:

``promote.eval-invalid`` an eval folder does not verify;
``promote.untrusted-eval`` its verdicts are signed by a key the policy does not list;
``promote.evals-not-candidate`` / ``promote.evals-not-baseline`` the verdicts score
another run than the candidate / the label's current holder;
``promote.dataset-mismatch`` the two sides scored different datasets;
``promote.n-below-minimum`` fewer paired items than ``min_n``;
``promote.ci-crosses-zero`` the bootstrap interval of the delta does not lie above 0;
``promote.not-significant`` the permutation test does not show a gain at ``alpha``;
``promote.missing-holdout`` / ``promote.holdout-not-held-out`` no holdout pair, or one
over the main dataset; the holdout must beat the baseline under the same test;
``promote.item-mismatch`` the two sides of a pair scored different item sets (no
cherry-picking: n is the full paired set, never a convenient subset);
``promote.approval-stale`` approvals that name another holder, label state or
label (each is bound to ``previous`` and ``sequence``, so a revert retires it);
``promote.missing-approver`` fewer valid approvals from listed approvers than required
(approvals signed by the promoting key or by an eval signer never count);
``promote.over-budget`` the declared spend exceeds the cap.

Advisory findings never block (owner decision D12); only these facts do.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

APPROVAL = "opentine.promotion-approval/1"
DECISION = "opentine.promotion-decision/1"
LABEL_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
RUN_RE = re.compile(r"run:sha256:[0-9a-f]{64}")
_KEYS = {"label_policy", "test", "alpha", "seed", "resamples", "min_n", "metric", "budget_usd",
         "approvers", "min_approvals", "require_holdout", "eval_signers"}  # fmt: skip


def refusal(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def load_policy(path: Path) -> dict[str, Any]:
    """``[promote]`` of a TOML file, checked; ``label_policy`` resolved next to it."""
    from opentine._eval_stats import DEFAULT_RESAMPLES, METRICS, check
    from opentine.remote._admission_policy import parse_policy

    data = tomllib.loads(Path(path).read_text("utf-8")).get("promote")
    if not isinstance(data, dict) or set(data) - _KEYS:
        raise ValueError(f"the promotion policy is a [promote] table of {', '.join(sorted(_KEYS))}")
    out = {"test": "paired-bootstrap", "alpha": "0.05", "seed": 0, "min_n": 30,
           "resamples": DEFAULT_RESAMPLES, "metric": "score", "min_approvals": 1,
           "require_holdout": True, **data}  # fmt: skip
    out["alpha"] = str(out["alpha"])
    check(out["test"], out["alpha"], out["seed"], out["resamples"])
    if out["metric"] not in METRICS:
        raise ValueError(f"metric is one of {', '.join(METRICS)}")
    for name in ("approvers", "eval_signers"):
        if not (
            isinstance(out.get(name), list)
            and out[name]
            and all(isinstance(x, str) and x.startswith("sha256:") for x in out[name])
        ):
            raise ValueError(f"{name} lists sha256: key fingerprints (at least one)")
    for name in ("min_n", "min_approvals"):
        if isinstance(out[name], bool) or not isinstance(out[name], int) or out[name] < 1:
            raise ValueError(f"{name} must be a positive integer")
    try:
        out["budget_usd"] = str(Decimal(str(out["budget_usd"])))
    except (KeyError, InvalidOperation) as exc:
        raise ValueError("budget_usd is required: the spend cap in USD") from exc
    if not isinstance(out.get("label_policy"), str):
        raise ValueError("label_policy names the opentine.admission-policy file for labels/*")
    target = (Path(path).parent / out["label_policy"]).resolve()
    label_bytes = target.read_bytes()
    out["admission"] = parse_policy("promotion", label_bytes)
    out["label_policy_sha256"] = hashlib.sha256(label_bytes).hexdigest()
    out["sha256"] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return out


def _eval(folder: Path, policy: dict[str, Any], runs: str | None, side: str, out: list,
          avoid: str | None = None) -> dict:  # fmt: skip
    from opentine._eval_run import read_verdicts, verify_eval

    checked = verify_eval(folder)
    rows = read_verdicts(folder) if checked["ok"] else []
    if not checked["ok"]:
        out.append(refusal("promote.eval-invalid", f"{side} eval {folder} does not verify"))
    signers = {row["signer"] for row in rows}
    if signers - set(policy["eval_signers"]):
        out.append(refusal("promote.untrusted-eval", f"{side} verdicts signed by an unlisted key"))
    if runs is not None and rows and {row["run"] for row in rows} != {runs}:
        code = "promote.evals-not-candidate" if side.endswith("candidate") else (
            "promote.evals-not-baseline")  # fmt: skip
        out.append(refusal(code, f"{side} verdicts do not all score {runs}"))
    scored = {row["run"] for row in rows}
    if runs is None and avoid is not None and rows and (len(scored) != 1 or avoid in scored):
        # A first promotion (or a canary over one): no holder to match, so the
        # baseline must still score one run, and not the candidate itself.
        out.append(refusal("promote.evals-not-baseline",
                           f"{side} verdicts must score one run other than {avoid}"))  # fmt: skip
    datasets = {row["dataset"] for row in rows}
    summary = Path(folder) / "eval.json"
    sha = (
        json.loads(summary.read_text("utf-8")).get("verdicts_sha256") if summary.is_file() else None
    )
    return {"eval": checked["eval"], "dataset": next(iter(datasets), None), "ok": checked["ok"],
            "verdicts_sha256": sha, "items": checked["items"]}  # fmt: skip


def _beats(pair: str, a: Path, b: Path, policy: dict[str, Any], out: list) -> dict | None:
    from opentine._eval_compare import statistical

    row = statistical(a, b, method=policy["test"], alpha=policy["alpha"], seed=policy["seed"],
                      resamples=policy["resamples"])  # fmt: skip
    if row["stats"] is None:
        # Fail closed: a pair the comparison cannot verify never counts as a gain.
        out.append(refusal("promote.eval-invalid", f"{pair}: the comparison does not verify"))
        return None
    from opentine._eval_run import read_verdicts

    if {r["item"] for r in read_verdicts(a)} != {r["item"] for r in read_verdicts(b)}:
        out.append(refusal("promote.item-mismatch", f"{pair}: the two sides scored other items"))
    if row["stats"]["n"] < policy["min_n"]:
        out.append(refusal("promote.n-below-minimum",
                           f"{pair}: n={row['stats']['n']} < min_n={policy['min_n']}"))  # fmt: skip
    m = row["stats"]["metrics"][policy["metric"]]
    if policy["test"] == "paired-bootstrap" and not (m["ci"] and Decimal(m["ci"][0]) > 0):
        out.append(
            refusal(
                "promote.ci-crosses-zero",
                f"{pair}: {policy['metric']} delta interval {m['ci']} is not above 0",
            )
        )
    if policy["test"] == "permutation" and not m["improvement"]:
        out.append(
            refusal(
                "promote.not-significant",
                f"{pair}: {policy['metric']} p={m['p_value']} delta={m['delta']}",
            )
        )
    return row


def gate(policy: dict[str, Any], *, candidate: str, label: str, current: str | None,
         baseline: Path, evals: Path, holdout: tuple[Path, Path] | None,
         approval_files: list[Path], spent: str,
         promoter: str = "", sequence: int = 0) -> tuple[dict[str, Any], list]:  # fmt: skip
    out: list[dict[str, str]] = []
    try:
        cost = Decimal(spent)
    except InvalidOperation as exc:
        raise ValueError(f"--spent {spent!r} is not a decimal") from exc
    if not cost.is_finite() or cost < 0:
        raise ValueError("--spent must be a non-negative decimal")
    sides = {"baseline": _eval(baseline, policy, current, "baseline", out, avoid=candidate),
             "candidate": _eval(evals, policy, candidate, "candidate", out)}  # fmt: skip
    if sides["baseline"]["dataset"] != sides["candidate"]["dataset"]:
        out.append(
            refusal("promote.dataset-mismatch", "baseline and candidate scored different datasets")
        )
    main = _beats("main", baseline, evals, policy, out) if not out else None
    held = None
    if holdout is None:
        if policy["require_holdout"]:
            out.append(refusal("promote.missing-holdout", "the policy requires a holdout pair"))
    else:
        sides["holdout_baseline"] = _eval(holdout[0], policy, current, "holdout baseline", out,
                                          avoid=candidate)  # fmt: skip
        sides["holdout_candidate"] = _eval(holdout[1], policy, candidate, "holdout candidate", out)
        if sides["holdout_candidate"]["dataset"] == sides["candidate"]["dataset"]:
            out.append(refusal("promote.holdout-not-held-out", "the holdout is the main dataset"))
        elif sides["holdout_baseline"]["dataset"] != sides["holdout_candidate"]["dataset"]:
            out.append(refusal("promote.dataset-mismatch", "the holdout sides differ"))
        elif all(s["ok"] for s in sides.values()):
            held = _beats("holdout", holdout[0], holdout[1], policy, out)
    from opentine._promote_pins import approvals

    exclude = frozenset({promoter, *policy["eval_signers"]})
    signed, stale = approvals(approval_files, candidate, label, policy, exclude,
                              previous=current, sequence=sequence)  # fmt: skip
    if len(signed) < policy["min_approvals"] and stale:
        out.append(refusal("promote.approval-stale", f"{stale} approval(s) were signed for "
                           "another holder or label state (a revert or later move)"))  # fmt: skip
    elif len(signed) < policy["min_approvals"]:
        out.append(
            refusal(
                "promote.missing-approver",
                f"{len(signed)} of {policy['min_approvals']} approvals from listed approvers "
                "(the promoting key and eval signers never count)",
            )
        )
    if cost > Decimal(policy["budget_usd"]):
        out.append(
            refusal("promote.over-budget", f"spent {spent} USD > cap {policy['budget_usd']}")
        )
    evidence = {"evals": sides, "main": main, "holdout": held,
                "approvals": [{"approver": who, "sha256": digest} for who, digest in signed],
                "spent_usd": spent, "budget_usd": policy["budget_usd"]}  # fmt: skip
    return evidence, out


__all__ = ["APPROVAL", "DECISION", "LABEL_RE", "RUN_RE", "gate", "load_policy",
           "refusal"]  # fmt: skip
