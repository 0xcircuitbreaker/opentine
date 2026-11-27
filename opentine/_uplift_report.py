"""``tine uplift horizon|compare`` reports (0.73), computed from an export only.

``horizon`` fits success against log2 task length for one condition (and
optionally one subject) and reports the 50%-success time horizon with a seeded
bootstrap interval, plus the same fit per lineage ``generation`` (the trend).
``compare`` sets two groups side by side: success rate, measured minutes on the
tasks both groups solved, perceived over measured minutes from speed records,
and each group's horizon. Both carry the export's digest, the seed and the
resample count, so anyone holding the export can recompute every number.
"""

from __future__ import annotations

import math
from fractions import Fraction
from typing import Any

from opentine._uplift_export import digest_of
from opentine._uplift_fit import fmt, horizon

#: Bounds that keep a caller from narrowing the interval: a handful of resamples or a large
#: alpha gives a narrow, flattering interval; a huge count only burns CPU.
MIN_RESAMPLES, MAX_RESAMPLES = 100, 100_000
MIN_ALPHA = Fraction(1, 1000)
#: 0.86: ``naive`` resamples points; ``cluster`` resamples clusters (task or subject), then
#: points inside each drawn cluster, so correlated attempts do not overstate precision.
METHODS, CLUSTER_KEYS = ("naive", "cluster"), ("task", "subject")


def _params(seed: int, resamples: int, alpha: str, method: str = "naive",
            cluster_key: str | None = None) -> dict[str, Any]:  # fmt: skip
    if method not in METHODS:
        raise ValueError(f"--bootstrap is one of {', '.join(METHODS)}")
    if method == "cluster":
        cluster_key = cluster_key or "task"
        if cluster_key not in CLUSTER_KEYS:
            raise ValueError(f"--cluster-key is one of {', '.join(CLUSTER_KEYS)}")
    else:
        cluster_key = None
    if not MIN_RESAMPLES <= resamples <= MAX_RESAMPLES:
        raise ValueError(f"--resamples is {MIN_RESAMPLES}..{MAX_RESAMPLES}")
    level = Fraction(alpha)
    if not MIN_ALPHA <= level <= Fraction(1, 2):
        raise ValueError("--alpha is between 0.001 and 0.5")
    return {"seed": seed, "resamples": resamples, "alpha": alpha, "bootstrap": method,
            "cluster_key": cluster_key}  # fmt: skip


def _select(export: dict[str, Any], condition: str, subject: str | None) -> list[dict]:
    return [r for r in export["records"] if r["condition"] == condition
            and (subject is None or r["subject"] == subject)]  # fmt: skip


def _points(export: dict[str, Any], rows: list[dict]) -> list[tuple[float, bool]]:
    lengths = {t["id"]: float(t["minutes"]) for t in export["definition"]["tasks"]}
    return [(math.log2(lengths[r["task"]]), bool(r["success"])) for r in _attempts(rows)]


def _attempts(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["record"] in ("baseline", "run")]


def _fit(export: dict, rows: list[dict], p: dict[str, Any]) -> dict[str, Any]:
    key = p["cluster_key"]
    clusters = [str(r[key]) for r in _attempts(rows)] if key else None
    return horizon(_points(export, rows), seed=p["seed"], resamples=p["resamples"],
                   alpha=float(Fraction(p["alpha"])), clusters=clusters)  # fmt: skip


def _ok(findings: list[dict], strict: bool) -> tuple[int, bool]:
    blocking = sum(1 for f in findings if f["level"] == "fail" or strict)
    return blocking, blocking == 0


def report_horizon(export: dict[str, Any], *, condition: str = "ai", subject: str | None = None,
                   seed: int = 0, resamples: int = 2000, alpha: str = "0.05",
                   strict: bool = False, bootstrap: str = "naive",
                   cluster_key: str | None = None) -> dict[str, Any]:  # fmt: skip
    """The horizon report for one condition (and subject) of an export."""
    p = _params(seed, resamples, alpha, bootstrap, cluster_key)
    rows = _select(export, condition, subject)
    fit = _fit(export, rows, p)
    gens = sorted({r["generation"] for r in rows if r["generation"] is not None})
    trend = [{"generation": g, **_fit(export, [r for r in rows if r["generation"] == g], p)}
             for g in gens]  # fmt: skip
    findings = list(export["findings"])
    if fit["status"] != "ok":
        why = f"no horizon: {fit['status']} ({fit['n']} points)"
        findings.append({"level": "fail", "code": "fail:uplift.fit-refused", "oid": "",
                         "message": why})  # fmt: skip
    elif fit["bootstrap_failed"] * 10 > p["resamples"]:
        findings.append({"level": "advisory", "code": "advisory:uplift.unstable-bootstrap",
                         "oid": "", "message": f"{fit['bootstrap_failed']} of "
                         f"{p['resamples']} resamples did not converge"})  # fmt: skip
    blocking, ok = _ok(findings, strict)
    return {"ok": ok, "strict": strict, "blocking": blocking, "suite": export["suite"],
            "export_digest": digest_of(export), "condition": condition, "subject": subject,
            **p, "fit": fit, "trend": trend, "findings": findings}  # fmt: skip


def _mean_minutes(rows: list[dict]) -> dict[str, Fraction]:
    table: dict[str, list[Fraction]] = {}
    for r in rows:
        if r["record"] != "speed" and r["success"] and r["minutes"] is not None:
            table.setdefault(r["task"], []).append(Fraction(r["minutes"]))
    return {task: sum(v, Fraction(0)) / len(v) for task, v in table.items()}


def _ratio(num: Fraction, den: Fraction) -> str | None:
    return fmt(float(num / den)) if den else None


def _group(export: dict, condition: str, subject: str | None, p: dict) -> tuple[dict, dict]:
    rows = _select(export, condition, subject)
    attempts = [r for r in rows if r["record"] != "speed"]
    wins = sum(1 for r in attempts if r["success"])
    speed = [r for r in rows if r["record"] == "speed"]
    perceived = sum((Fraction(r["perceived_minutes"]) for r in speed), Fraction(0))
    measured = sum((Fraction(r["minutes"]) for r in speed), Fraction(0))
    return {"condition": condition, "subject": subject, "attempts": len(attempts),
            "successes": wins, "success_rate": _ratio(Fraction(wins), Fraction(len(attempts))),
            "speed_records": len(speed), "perceived_over_measured": _ratio(perceived, measured),
            "fit": _fit(export, rows, p)}, _mean_minutes(rows)  # fmt: skip


def report_compare(export: dict[str, Any], a: tuple[str, str | None], b: tuple[str, str | None],
                   *, seed: int = 0, resamples: int = 2000, alpha: str = "0.05",
                   strict: bool = False, bootstrap: str = "naive",
                   cluster_key: str | None = None) -> dict[str, Any]:  # fmt: skip
    """Two groups side by side; ``b_over_a_minutes`` > 1 means B took longer."""
    p = _params(seed, resamples, alpha, bootstrap, cluster_key)
    ga, ma = _group(export, *a, p)
    gb, mb = _group(export, *b, p)
    paired = sorted(set(ma) & set(mb))
    total_a = sum((ma[t] for t in paired), Fraction(0))
    total_b = sum((mb[t] for t in paired), Fraction(0))
    findings = list(export["findings"])
    blocking, ok = _ok(findings, strict)
    return {"ok": ok, "strict": strict, "blocking": blocking, "suite": export["suite"],
            "export_digest": digest_of(export), **p, "a": ga, "b": gb,
            "paired_tasks": len(paired), "b_over_a_minutes": _ratio(total_b, total_a),
            "findings": findings}  # fmt: skip


def selector(text: str) -> tuple[str, str | None]:
    """``CONDITION`` or ``CONDITION:SUBJECT``."""
    from opentine._uplift import CONDITIONS

    condition, _sep, subject = text.partition(":")
    if condition not in CONDITIONS:
        raise ValueError(f"{text!r}: the condition is one of {', '.join(CONDITIONS)}")
    return condition, subject or None


__all__ = ["report_compare", "report_horizon", "selector"]
