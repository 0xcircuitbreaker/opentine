"""``tine stats`` over a v3 repository: counted from the object store itself.

The legacy path aggregates the rebuildable ``.tine_runs`` index, which a v3
repository never writes, so a repository's runs used to be invisible (or
whatever stray legacy files sat beside it got reported as its numbers). This
mode walks every stored object once: ``run:`` objects are the runs, a run's cost
and step count are the sum over the events it lists (the same totals
``load_run`` would rebuild), and ``bytes`` are canonical object bytes, the same
figure ``tine du`` reports as ``raw_bytes``.

An object that will not decode is counted under ``unreadable`` and excluded
from every other number, mirroring the legacy mode's corrupt-row rule.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine._cli_common import BRAND, BRAND_DIM, _cost_str, _terminal, console
from opentine._cli_json import emit

STATS_REPO_SCOPE = "v3-repository"
STATS_REPO_NOTE = "scope: every object in the v3 repository's store (reachable or not)"
REPO_GROUP_BY = ("model", "status", "day")
_LEGACY_ONLY = ("tag", "model", "status", "cost_min", "cost_max", "since", "until", "grep")


def wants_repo(args: argparse.Namespace) -> bool:
    """``--repo`` given, the cwd holds a repository, or ``--ai-share`` (git) was asked."""
    if getattr(args, "ai_share", False):
        return True
    if getattr(args, "repo", None):
        return True
    return (Path(".tine") / "config.json").is_file()


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _day(created_at: float | None) -> str:
    try:
        return datetime.fromtimestamp(float(created_at), UTC).strftime("%Y-%m-%d")
    except (TypeError, OSError, OverflowError, ValueError):
        return "(undated)"


def collect(repo) -> dict[str, Any]:
    """Ground facts for every object: per-run rows plus store-wide counts."""
    from opentine.repository._du import object_sizes

    sizes = object_sizes(repo)
    events: dict[str, dict[str, Any]] = {}
    run_payloads: dict[str, dict[str, Any]] = {}
    unreadable = 0
    for oid in sorted(sizes):
        kind = oid.split(":", 1)[0]
        if kind not in ("run", "event"):
            continue
        try:
            payload = repo.get(oid).payload()
        except Exception:
            unreadable += 1
            continue
        (run_payloads if kind == "run" else events)[oid] = payload
    runs = []
    for oid, payload in run_payloads.items():
        listed = [item for item in payload.get("events") or [] if isinstance(item, str)]
        known = [events[item] for item in listed if item in events]
        runs.append(
            {
                "run": oid,
                "model": str(payload.get("model") or "(none)"),
                "status": str(payload.get("status") or "(none)"),
                "created_at": payload.get("created_at"),
                "events": len(listed),
                "cost": sum(_number(event.get("cost")) for event in known),
            }
        )
    blobs = [oid for oid in sizes if oid.startswith("blob:")]
    return {
        "runs": runs,
        "objects": len(sizes),
        "events": len(events),
        "blobs": len(blobs),
        "blob_bytes": sum(sizes[oid][0] for oid in blobs),
        "bytes": sum(value[0] for value in sizes.values()),
        "stored_bytes": sum(value[1] for value in sizes.values()),
        "unreadable": unreadable,
    }


def aggregate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    count = len(runs)
    costs = [row["cost"] for row in runs]
    steps = sum(row["events"] for row in runs)
    times = [float(row["created_at"]) for row in runs if row["created_at"] is not None]
    return {
        "runs": count,
        "steps_total": steps,
        "steps_mean": (steps / count) if count else 0.0,
        "cost_total": sum(costs),
        "cost_mean": (sum(costs) / count) if count else 0.0,
        "cost_max": max(costs) if costs else 0.0,
        "models": sorted({row["model"] for row in runs}),
        "statuses": sorted({row["status"] for row in runs}),
        "first_created_at": min(times) if times else None,
        "last_created_at": max(times) if times else None,
    }


def _groups(runs: list[dict[str, Any]], group_by: str, limit: int) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for row in runs:
        key = _day(row["created_at"]) if group_by == "day" else row[group_by]
        buckets.setdefault(key, []).append(row)
    rows = [{"key": key, **aggregate(members)} for key, members in buckets.items()]
    rows.sort(key=lambda row: (-row["cost_total"], row["key"]))
    return rows[:limit] if limit and limit > 0 else rows


def _refuse(message: str) -> None:
    console.print(f"[red]{_terminal(message)}[/]")
    raise SystemExit(1)


def cmd_stats_repo(args: argparse.Namespace) -> None:
    if getattr(args, "ai_share", False):
        from opentine._cli_attribute import cmd_ai_share

        return cmd_ai_share(args)
    from opentine.repository import Repo

    used = [name for name in _LEGACY_ONLY if getattr(args, name, None)]
    if used or getattr(args, "deep", False):
        flags = ", ".join("--" + name.replace("_", "-") for name in used or ["deep"])
        _refuse(f"{flags}: legacy-index only; not supported over a v3 repository yet")
    group_by = getattr(args, "group_by", None)
    if group_by and group_by not in REPO_GROUP_BY:
        _refuse(f"--group-by over a v3 repository must be one of {', '.join(REPO_GROUP_BY)}")
    try:
        facts = collect(Repo.open(getattr(args, "repo", None) or "."))
    except (OSError, ValueError) as exc:  # KernelError is a ValueError
        _refuse(str(exc))
    totals = aggregate(facts["runs"])
    store = {key: value for key, value in facts.items() if key != "runs"}
    groups = _groups(facts["runs"], group_by, args.limit) if group_by else []
    if getattr(args, "json", False):
        emit(
            {
                "command": "stats",
                "scope": STATS_REPO_SCOPE,
                "scope_note": STATS_REPO_NOTE,
                "deep": False,
                "group_by": group_by,
                "unreadable": facts["unreadable"],
                "store": store,
                "totals": totals,
                "groups": groups,
            }
        )
        return
    console.print(
        f"[{BRAND}]# Stats[/] {totals['runs']} run(s)  events={store['events']}  "
        f"blobs={store['blobs']}  objects={store['objects']}  bytes={store['bytes']}  "
        f"cost={_cost_str(totals['cost_total'])}"
    )
    console.print(f"  models: {_terminal(', '.join(totals['models'])) or '-'}")
    if store["unreadable"]:
        console.print(f"  [red]unreadable:[/] {store['unreadable']} object(s), excluded")
    for row in groups:
        console.print(
            f"  {_terminal(row['key'])}  {row['runs']} run(s)  {_cost_str(row['cost_total'])}"
        )
    console.print(f"[{BRAND_DIM}]{STATS_REPO_NOTE}[/]")
