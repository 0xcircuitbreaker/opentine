"""Uplift records and trend points in the query index (0.73).

* ``uplift_suites``: one row per ``opentine.uplift-suite/1`` attestation
  (:mod:`opentine._uplift`), held or not;
* ``uplift_records``: one row per ``opentine.uplift-record/1`` attestation:
  baselines, runs and speed records, with the lineage ``generation`` they name;
* ``trend_points``: one row per variant of the 0.58 lineage folder that
  ``tine trends`` would report, with its ``generation`` (depth in the parent
  graph), the point estimates (mean score, pass rate, cost per success) and its
  flags. The row's ``oid`` is the variant's lineage record, so it joins
  ``lineage_variants`` and ``lineage_edges``. Intervals, horizons and
  regressions need the bootstrap and stay in ``tine trends``.

``signed`` is 1 only when the Ed25519 signature verifies *and* the payload's
``signer`` names the key that signed (for a trend point: its lineage record).
Under ``--verify`` an uplift row is ``verified`` only for a pinned ``scorer`` or
``eval`` signer that holds no ``optimizer`` role; a trend point is re-derived
from the lineage folder and must match column for column. Rows are derived and
non-authoritative: ``tine uplift`` and ``tine trends`` decide.
"""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path
from typing import Any

COLUMNS: dict[str, tuple[str, ...]] = {
    "uplift_suites": ("oid", "target", "signer", "signed", "digest", "name", "version",
                      "tasks", "at"),
    "uplift_records": ("oid", "target", "signer", "signed", "record", "suite", "task",
                       "subject", "condition", "success", "minutes", "perceived_minutes",
                       "generation", "at"),
    "trend_points": ("oid", "variant", "signer", "signed", "loop", "generation", "parents",
                     "n", "score", "pass_rate", "cost_per_success", "flags", "withheld"),
}  # fmt: skip
ROLES_FOR = {"uplift_suites": ("scorer", "eval"), "uplift_records": ("scorer", "eval")}
_NO_LENGTHS = {"dataset": None, "lengths": {}}


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def attestation_rows(oid: str, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from opentine._query_containment import _signed
    from opentine._uplift import RECORD, SUITE

    claim = payload.get("claim")
    convention = claim.get("convention") if isinstance(claim, dict) else None
    if convention not in (SUITE, RECORD):
        return {}
    head = {"oid": oid, "target": _text(payload.get("target_id")),
            "signer": _text(payload.get("signer")), "signed": _signed(payload)}  # fmt: skip
    if convention == SUITE:
        suite = claim.get("suite") if isinstance(claim.get("suite"), dict) else {}
        tasks = suite.get("tasks")
        return {"uplift_suites": [{
            **head, "digest": _text(claim.get("digest")), "name": _text(suite.get("name")),
            "version": _text(suite.get("version")),
            "tasks": len(tasks) if isinstance(tasks, list) else None,
            "at": _text(claim.get("at"))}]}  # fmt: skip
    success = claim.get("success")
    return {"uplift_records": [{
        **head, "record": _text(claim.get("record")), "suite": _text(claim.get("suite")),
        "task": _text(claim.get("task")), "subject": _text(claim.get("subject")),
        "condition": _text(claim.get("condition")),
        "success": int(success) if isinstance(success, bool) else None,
        "minutes": _text(claim.get("minutes")),
        "perceived_minutes": _text(claim.get("perceived_minutes")),
        "generation": _int(claim.get("generation")), "at": _text(claim.get("at"))}]}  # fmt: skip


def _mean(values: list[int], scale: int) -> str | None:
    from opentine._eval_stats import text

    return text(Fraction(sum(values), len(values) * scale)) if values else None


def trend_rows(store: Path, files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    """``trend_points`` for the lineage *files*, trusted as ``tine trends`` would."""
    import hashlib

    from opentine._eval_stats import MICRO, micro
    from opentine._lineage_trust import load_trust
    from opentine._query_rows import lineage_rows
    from opentine._trends import _cost
    from opentine._trends_collect import WITHHOLD, collect

    if not any(name.startswith("variants/") for name in files):
        return {"trend_points": []}
    root = Path(store).parent if Path(store).name == ".tine" else Path(store)
    export, _excluded = collect(root, files, lengths=_NO_LENGTHS, trust=load_trust(root),
                                alpha="0.05", seed=0, resamples=100)  # fmt: skip
    heads = {r["variant"]: r for r in lineage_rows(files)["lineage_variants"]}
    out = []
    for row in export["variants"]:
        items, head = row["items"], heads.get(row["variant"])
        if head is None:
            continue
        name = f"variants/{row['variant'][7:]}.json"
        oid = "sha256:" + hashlib.sha256(files[name]).hexdigest()
        out.append({
            "oid": oid, "variant": row["variant"], "signer": head["signer"],
            "signed": head["signed"], "loop": row["loop"], "generation": row["generation"],
            "parents": ",".join(row["parents"]), "n": len(items),
            "score": _mean([micro(i["score"]) for i in items], MICRO),
            "pass_rate": _mean([int(bool(i["passed"])) for i in items], 1),
            "cost_per_success": _cost(row, sum(1 for i in items if i["passed"])),
            "flags": ",".join(row["flags"]),
            "withheld": int(bool(WITHHOLD & set(row["flags"])))})  # fmt: skip
    return {"trend_points": out}


def derive(store: Path, files: dict[str, bytes], oid: str) -> tuple[dict | None, str | None]:
    """The trend point the lineage folder derives for *oid* now."""
    for row in trend_rows(store, files)["trend_points"]:
        if row["oid"] == oid:
            return row, None
    return None, "the lineage folder derives no trend point for this record"


def trust_digest(store: Path) -> str:
    """What trend points depend on beyond the lineage folder and objects: pinned roles."""
    import hashlib
    import json

    from opentine._key_roles_pin import resolve

    found = resolve(Path(store))
    body = json.dumps({"status": found["status"], "roles": found["roles"]}, sort_keys=True)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


__all__ = ["COLUMNS", "ROLES_FOR", "attestation_rows", "derive", "trend_rows", "trust_digest"]
