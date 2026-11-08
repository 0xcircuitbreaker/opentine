"""``tine eval run|verify|compare``: score a dataset, sign verdicts, diff two evals (0.45).

An eval writes a folder::

    eval.json       tine-eval/1 summary (unsigned; every fact in it is re-derived
                    from the verdicts by ``verify_eval``)
    verdicts.jsonl  one signed tine-eval-verdict/1 per dataset item, in item order

The eval id is ``sha256:`` over ``opentine.eval.v1:`` + JCS of the dataset
digest, scorer, scorer version, threshold, creation time and signer, so two
evals of the same dataset at the same second by the same key with the same
scorer are the same eval.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from opentine import _eval_verdict as verdicts
from opentine._eval_dataset import DatasetError, dataset_digest, item_digest
from opentine._eval_scorers import Scorer
from opentine.kernel import canonical_json

SCHEMA = "tine-eval/1"
EVAL_DOMAIN = b"opentine.eval.v1:"
SUMMARY, VERDICTS = "eval.json", "verdicts.jsonl"


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def eval_id(fields: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(EVAL_DOMAIN + canonical_json(fields)).hexdigest()


def run_eval(
    items: list[dict[str, Any]],
    scorer: Scorer,
    private_key: Any,
    out_dir: Path,
    *,
    threshold: float = 1.0,
    outputs: dict[str, dict[str, Any]] | None = None,
    default_run: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Score every item, sign one verdict each, write the eval folder; the summary."""
    from opentine._canon import atomic_write_text
    from opentine._signing_keys import load_ed25519_private
    from opentine._signing_pins import key_fingerprint

    private = load_ed25519_private(private_key)
    signer = key_fingerprint(private.public_key().public_bytes_raw())
    when = created_at or now()
    data = dataset_digest(items)
    pinned = {
        "dataset": data,
        "scorer": scorer.id,
        "scorer_version": scorer.version,
        "threshold": verdicts.score_text(threshold),
        "created_at": when,
        "signer": signer,
    }
    ident = eval_id(pinned)
    lines: list[str] = []
    for item in items:
        given = (outputs or {}).get(item["id"], item)
        if "output" not in given:
            raise DatasetError(f"item {item['id']!r} has no output to score")
        run = given.get("run") or item.get("run") or default_run
        if not run:
            raise DatasetError(f"item {item['id']!r} names no run: pass --run or --from-run items")
        score, judge = scorer(item, given["output"])
        verdict = verdicts.make(
            private, eval=ident, dataset=data, item=item["id"], item_digest=item_digest(item),
            run=run, scorer=scorer.id, scorer_version=scorer.version, score=score,
            threshold=threshold, judge_run=judge, created_at=when,
        )  # fmt: skip
        lines.append(json.dumps(verdict, sort_keys=True, ensure_ascii=False) + "\n")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    body = "".join(lines)
    atomic_write_text(out / VERDICTS, body)
    summary = {"schema": SCHEMA, "eval": ident, **pinned, **_tally(lines),
               "verdicts_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest()}  # fmt: skip
    atomic_write_text(out / SUMMARY, json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def _tally(lines: list[str]) -> dict[str, Any]:
    rows = [json.loads(line) for line in lines]
    total = sum((Decimal(row["score"]) for row in rows), Decimal(0))
    mean = verdicts.score_text(total / len(rows)) if rows else "0"
    passed = sum(1 for row in rows if row["passed"])
    return {"items": len(rows), "passed": passed, "failed": len(rows) - passed, "mean_score": mean}


def read_verdicts(folder: Path) -> list[dict[str, Any]]:
    path = Path(folder)
    path = path / VERDICTS if path.is_dir() else path
    text = path.read_text("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def verify_eval(folder: Path, *, public_key: bytes | None = None) -> dict[str, Any]:
    """Every verdict checked; the summary, if present, must match what they say.

    Returns ``{ok, eval, items, passed, failed, mean_score, failures: [...]}``;
    each failure names the line, item and ``eval-verdict.*`` code.
    """
    folder = Path(folder)
    rows = read_verdicts(folder)
    failures: list[dict[str, Any]] = []
    evals, seen, good = set(), set(), []
    for number, row in enumerate(rows, 1):
        try:
            verdicts.verify(row, public_key=public_key)
        except verdicts.EvalVerdictError as exc:
            item = row.get("item") if isinstance(row, dict) else None
            failures.append({"line": number, "item": item, "reason": exc.code, "detail": str(exc)})
            continue
        evals.add(row["eval"])
        good.append(json.dumps(row))
        if row["item"] in seen:
            failures.append({"line": number, "item": row["item"], "reason": "eval.duplicate-item"})
        seen.add(row["item"])
    if len(evals) > 1:
        failures.append({"line": 0, "item": None, "reason": "eval.mixed-evals"})
    tally = _tally(good)
    summary_path = folder / SUMMARY if folder.is_dir() else None
    if summary_path is not None and summary_path.is_file():
        summary = json.loads(summary_path.read_text("utf-8"))
        claimed = {k: summary.get(k) for k in ("items", "passed", "failed", "mean_score")}
        if claimed != tally or (evals and summary.get("eval") not in evals):
            failures.append({"line": 0, "item": None, "reason": "eval.summary-mismatch"})
    ident = next(iter(evals)) if len(evals) == 1 else None
    return {"ok": not failures and bool(rows), "eval": ident, **tally, "failures": failures}


def compare(left: Path, right: Path, *, public_key: bytes | None = None) -> dict[str, Any]:
    """Both evals verified, then item by item: regressions, fixes and score changes."""
    checks = [verify_eval(side, public_key=public_key) for side in (left, right)]
    a = {row["item"]: row for row in read_verdicts(left)}
    b = {row["item"]: row for row in read_verdicts(right)}
    regressed, fixed, changed = [], [], []
    for item in sorted(set(a) & set(b)):
        old, new = a[item], b[item]
        if old["passed"] and not new["passed"]:
            regressed.append(item)
        elif new["passed"] and not old["passed"]:
            fixed.append(item)
        if old["score"] != new["score"]:
            delta = Decimal(new["score"]) - Decimal(old["score"])
            changed.append({"item": item, "from": old["score"], "to": new["score"],
                            "delta": f"{delta:f}"})  # fmt: skip
    first = next(iter(a.values()), {})
    second = next(iter(b.values()), {})
    same = {k: first.get(k) == second.get(k) for k in ("dataset", "scorer", "scorer_version")}
    mean_delta = Decimal(checks[1]["mean_score"]) - Decimal(checks[0]["mean_score"])
    return {
        "ok": checks[0]["ok"] and checks[1]["ok"],
        "a": {"eval": checks[0]["eval"], "ok": checks[0]["ok"], "passed": checks[0]["passed"]},
        "b": {"eval": checks[1]["eval"], "ok": checks[1]["ok"], "passed": checks[1]["passed"]},
        "same": same,
        "mean_delta": f"{mean_delta:f}",
        "regressed": regressed,
        "fixed": fixed,
        "changed": changed,
        "only_a": sorted(set(a) - set(b)),
        "only_b": sorted(set(b) - set(a)),
    }


__all__ = ["SCHEMA", "compare", "eval_id", "read_verdicts", "run_eval", "verify_eval"]
