"""Build an ``opentine.trends/1`` export from signed records only (0.72).

Inputs, each re-checked here and none trusted for being on disk:

* the 0.58 lineage folder: a variant counts only when its record verifies
  under its signer (``_lineage_check._node``); its generation is its depth in
  the parent graph (roots 0, else one more than its deepest recorded parent);
  variants on a parent cycle are excluded;
* the signed eval verdicts each record cites: a variant whose evals are
  absent, unsigned or signed by an untrusted key keeps its row with no items,
  flagged with the lineage code;
* the budget ledger's signed ``spend`` entries for the mutation run (0.69),
  for the cost per success;
* signed task lengths (:mod:`opentine._trends_lengths`) for the time horizon.

Flags are the lineage codes: ``lineage.score-tainted`` (0.59 taint on the
mutation run), ``lineage.memory-quarantined`` (0.61), and the ``tine lineage
check`` findings about the variant's own record.
"""

from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path
from typing import Any

from opentine._trends import CONVENTION

WITHHOLD = {"lineage.evidence-missing", "lineage.signer-untrusted"}


def _generations(parents: dict[str, list[str]]) -> tuple[dict[str, int], list[str]]:
    """Depth of every variant not on or behind a cycle (Kahn), and the rest."""
    from opentine._lineage_index import cyclic

    edges = [{"child": c, "parent": p} for c, ps in parents.items() for p in ps if p in parents]
    stuck = set(cyclic(edges))
    depth: dict[str, int] = {}
    pending = sorted(v for v in parents if v not in stuck)
    while pending:
        later = []
        for v in pending:
            known = [p for p in parents[v] if p in parents]
            if all(p in depth for p in known):
                depth[v] = 1 + max((depth[p] for p in known), default=-1)
            else:
                later.append(v)
        if len(later) == len(pending):
            stuck |= set(later)
            break
        pending = later
    return depth, sorted(stuck)


def _items(files: dict[str, bytes], claim: dict, lengths: dict[str, str]) -> list[dict]:
    from opentine._lineage import loads

    seen: dict[str, dict[str, Any]] = {}
    for row in claim["evals"]:
        raw = files.get(f"evals/{row['eval'][7:]}.jsonl", b"")
        for line in raw.decode("utf-8", "replace").split("\n"):
            if line.strip():
                verdict = loads(line)
                seen.setdefault(verdict["item"], {
                    "item": verdict["item"], "score": verdict["score"],
                    "passed": bool(verdict["passed"]),
                    "minutes": lengths.get(verdict["item"])})  # fmt: skip
    return [seen[k] for k in sorted(seen)]


def _costs(root: Path) -> dict[str, int]:
    """Micro-USD per run from signed budget-ledger spend entries (each entry once)."""
    from opentine import _budget_ledger as ledger
    from opentine.repository import Repo
    from opentine.repository._holds import BUDGET_LEDGER

    try:
        repo = Repo.open(root)
    except Exception:  # noqa: BLE001 - no repository: no ledger
        return {}
    out: dict[str, int] = {}
    for oid in ledger.held_ids(repo, BUDGET_LEDGER):
        row = ledger.read(repo, oid)
        value = row["value"] if row and row["signed"] else {}
        cost = value.get("cost") if value.get("entry") == "spend" else None
        if isinstance(cost, dict) and isinstance(value.get("run"), str):
            usd = Decimal(str(cost.get("total_cost", 0))) * 1_000_000
            micro = int(usd.quantize(Decimal(1), rounding=ROUND_HALF_EVEN))
            out[value["run"]] = out.get(value["run"], 0) + micro
    return out


def _flags(root: Path, files: dict[str, bytes], variant: str, found: list[dict]) -> list[str]:
    from opentine._integrity_run import lineage_findings
    from opentine._memory_quarantine import lineage_findings as memory

    extra = lineage_findings(root, files, [variant]) + memory(root, files, [variant])
    return sorted({f["code"] for f in found + extra})


def collect(root: Path, files: dict[str, bytes], *, lengths: dict[str, str], trust: Any,
            alpha: str, seed: int, resamples: int,
            loop: str | None = None) -> tuple[dict[str, Any], list[dict[str, str]]]:  # fmt: skip
    """``(export, excluded)``: the export and the variants left out, with why."""
    from opentine._lineage import loads
    from opentine._lineage_check import _node

    claims: dict[str, dict] = {}
    found: dict[str, list[dict]] = {}
    excluded: list[dict[str, str]] = []
    for name in sorted(files):
        if not (name.startswith("variants/") and name.endswith(".json")):
            continue
        variant = "sha256:" + name[len("variants/") : -len(".json")]
        out: list[dict[str, str]] = []
        _node(files, variant, out, trust)
        if any(f["code"] == "lineage.record-invalid" for f in out):
            excluded.append({"variant": variant, "code": "lineage.record-invalid"})
            continue
        claim = loads(files[name])["claim"]
        if loop is not None and claim["loop"] != loop:
            continue
        claims[variant], found[variant] = claim, out
    depth, stuck = _generations({v: c["parents"] for v, c in claims.items()})
    excluded += [{"variant": v, "code": "lineage.cycle"} for v in stuck]
    costs = _costs(root)
    rows = []
    for variant in sorted(depth, key=lambda v: (depth[v], v)):
        claim = claims[variant]
        missing = [{"code": "lineage.parent-missing"} for p in claim["parents"] if p not in claims]
        flags = _flags(root, files, variant, found[variant] + missing)
        keep = not WITHHOLD & set(flags)
        rows.append(
            {
                "variant": variant,
                "generation": depth[variant],
                "parents": list(claim["parents"]),
                "loop": claim["loop"],
                "flags": flags,
                "items": _items(files, claim, lengths) if keep else [],
                "cost_micro_usd": costs.get(claim["mutation_run"]) if keep else None,
            }
        )
    export = {"convention": CONVENTION, "alpha": alpha, "seed": seed, "resamples": resamples,
              "variants": rows}  # fmt: skip
    return export, sorted(excluded, key=lambda e: (e["variant"], e["code"]))


__all__ = ["collect"]
