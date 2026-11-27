"""Holdout query accounting (0.86): every eval against a sealed holdout is counted.

An eval that scores a sealed holdout reveals something about it (the pass
count and the mean score), so a loop that keeps re-evaluating variants against
the same holdout and keeping the best one is fitting to the holdout. Access
records count unseals; this module counts queries.

After ``tine eval run`` signs an eval whose items are a sealed holdout (named
with ``--holdout DIR``, or a folder under ``.tine/holdouts/`` whose commitment
``dataset`` equals the eval's dataset), it signs, with the eval key, a record
whose claim follows ``opentine.holdout.query/1``::

    {"schema": "opentine.holdout.query/1", "holdout": NAME, "root": HEX,
     "lineage": NODE, "eval": "sha256:...", "verdicts_sha256": HEX,
     "dataset": "sha256:...", "revealed": {"items": N, "passed": N, "mean_score": DEC},
     "count": K, "max_queries": Q|null, "over_budget": BOOL}

``count`` is the number of distinct evals recorded for that lineage node on
that holdout, this one included. ``max_queries`` is the commitment's
``budget.max_queries`` (``tine dataset seal --max-queries``); a commitment
without one has no query budget. The record is written to
``DIR/queries/HEX.json`` and kept as a held blob (target
``holdout-query:ROOT:HEX``) that ``tine hold release`` refuses, so deleting a
file lowers no count. Counting only: no noise is added to what an eval reveals.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

QUERY = "opentine.holdout.query/1"
MODES = ("advisory", "required")
FLAG = "holdout.query-over-budget"
UNATTRIBUTED = "unattributed"


def _raw(folder: Path | None, repo: Path | None, prefix: str) -> list[bytes]:
    from opentine._holdout import HoldoutError
    from opentine._holdout_hold import kept
    from opentine.repository._holds import HoldError

    found: dict[str, bytes] = {}
    if folder is not None:
        for path in sorted((Path(folder) / "queries").glob("*.json")):
            raw = path.read_bytes()
            found[hashlib.sha256(raw).hexdigest()] = raw
    try:
        for _target, raw in kept(repo, prefix):
            found[hashlib.sha256(raw).hexdigest()] = raw
    except HoldError as exc:  # fail closed: never count fewer queries than were held
        raise HoldoutError("holdout.holds", str(exc)) from exc
    return [found[k] for k in sorted(found)]


def _records(raws: list[bytes], root: str | None = None) -> list[dict[str, Any]]:
    """The validly signed query claims (signer bound to the key), optionally for one root."""
    from opentine._holdout import signer

    out = []
    for raw in raws:
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError:
            continue
        rec = doc.get("claim") if isinstance(doc, dict) else None
        if not (isinstance(rec, dict) and rec.get("schema") == QUERY
                and isinstance(rec.get("lineage"), str) and isinstance(rec.get("eval"), str)
                and (root is None or rec.get("root") == root)):  # fmt: skip
            continue
        who = signer(doc)
        if who is not None:
            out.append({**rec, "_signer": who})
    return out


def _prefix(root: str) -> str:
    from opentine.repository._holds import HOLDOUT_QUERY

    return f"{HOLDOUT_QUERY}{root}:"


def counts(folder: Path, repo: Path | None = None) -> dict[str, Any]:
    """``{max_queries, total, lineages: {NODE: N}, over_budget: [NODE...]}`` for a holdout."""
    from opentine._holdout import load

    claim = load(folder)["claim"]
    limit = claim["budget"].get("max_queries")
    seen: dict[str, set[str]] = {}
    for rec in _records(_raw(folder, repo, _prefix(claim["root"])), claim["root"]):
        seen.setdefault(rec["lineage"], set()).add(rec["eval"])
    lineages = {name: len(evals) for name, evals in sorted(seen.items())}
    over = [n for n, c in lineages.items() if isinstance(limit, int) and c > limit]
    return {"max_queries": limit, "total": sum(lineages.values()), "lineages": lineages,
            "over_budget": over}  # fmt: skip


def record(folder: Path, key: Any, summary: dict[str, Any], *, repo: Path | None,
           lineage: str | None, at: str) -> dict[str, Any]:  # fmt: skip
    """Sign, hold and write the query record for one signed eval *summary*."""
    from opentine._holdout import load, sign
    from opentine._holdout_hold import keep

    claim = load(folder)["claim"]
    node = lineage or UNATTRIBUTED
    state = counts(folder, repo)
    before = {r["eval"] for r in _records(_raw(folder, repo, _prefix(claim["root"])),
                                          claim["root"]) if r["lineage"] == node}  # fmt: skip
    count = len(before | {summary["eval"]})
    limit = state["max_queries"]
    rec = {"schema": QUERY, "holdout": claim["holdout"], "root": claim["root"], "lineage": node,
           "eval": summary["eval"], "verdicts_sha256": summary["verdicts_sha256"],
           "dataset": summary["dataset"],
           "revealed": {"items": summary["items"], "passed": summary["passed"],
                        "mean_score": summary["mean_score"]},
           "count": count, "max_queries": limit,
           "over_budget": isinstance(limit, int) and count > limit}  # fmt: skip
    data = (json.dumps(sign(key, rec, f"sha256:{claim['root']}", at), indent=2,
                       sort_keys=True) + "\n").encode("utf-8")  # fmt: skip
    sha = hashlib.sha256(data).hexdigest()
    keep(repo, _prefix(claim["root"]) + sha, data)  # first: a lost file still counts
    path = Path(folder) / "queries" / f"{sha}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {
        "holdout": claim["holdout"],
        "lineage": node,
        "count": count,
        "max_queries": limit,
        "over_budget": rec["over_budget"],
        "record": path.as_posix(),
        "sha256": sha,
    }


def folders_for(named: str | None, dataset: str, repo: Path | None) -> list[Path]:
    """The named holdout plus every repository holdout whose commitment is *dataset*."""
    from opentine._holdout import HoldoutError, load
    from opentine._promote_holdout import sealed_folders

    out = []
    for folder in sealed_folders([Path(named)] if named else [], repo):
        try:
            same = load(folder)["claim"].get("dataset") == dataset
        except HoldoutError:
            if named and Path(folder) == Path(named):
                raise
            continue
        if same or (named and Path(folder) == Path(named)):
            out.append(folder)
    return out


def over_budget_evals(repo: Path | None) -> set[str]:
    """Eval ids whose held query record says the query went over budget (for trends)."""
    from opentine.repository._holds import HOLDOUT_QUERY

    return {r["eval"] for r in _records(_raw(None, repo, HOLDOUT_QUERY)) if r.get("over_budget")}


def check_policy(policy: dict[str, Any]) -> None:
    """Settle ``holdout_queries`` in a ``[promote]`` table: required under the rsi profile."""
    rsi = policy.get("profile") == "rsi"
    mode = policy.get("holdout_queries", "required" if rsi else "advisory")
    if mode not in MODES:
        raise ValueError(f"holdout_queries is one of {', '.join(MODES)}")
    if rsi and mode != "required":
        raise ValueError('the rsi profile requires holdout_queries = "required"')
    policy["holdout_queries"] = mode


def promote_findings(folders: list[Path], repo: Path | None,
                     policy: dict[str, Any]) -> tuple[list[dict], list[dict]]:  # fmt: skip
    """``(refusals, advisories)``: a holdout whose query budget some lineage node exceeded."""
    from opentine._holdout import HoldoutError
    from opentine._promote_checks import refusal

    found = []
    for folder in folders:
        try:
            state = counts(folder, repo)
            name = Path(folder).as_posix()
        except HoldoutError:
            continue  # an unreadable holdout is refused as promote.holdout-exposed
        for node in state["over_budget"]:
            found.append(f"{name}: lineage {node} made {state['lineages'][node]} queries "
                         f"(budget {state['max_queries']}); rotate the holdout")  # fmt: skip
    if not found:
        return [], []
    if policy.get("holdout_queries", "advisory") == "required":
        return [refusal("promote.holdout-query-budget", d) for d in found], []
    return [], [{"code": "advisory:holdout.query-budget", "detail": d} for d in found]


__all__ = ["FLAG", "MODES", "QUERY", "check_policy", "counts", "folders_for",
           "over_budget_evals", "promote_findings", "record"]  # fmt: skip
