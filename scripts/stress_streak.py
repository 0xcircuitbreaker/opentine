#!/usr/bin/env python3
"""Report the nightly stress green streak from the GitHub Actions API (criterion 5).

    python scripts/stress_streak.py --repo OWNER/NAME [--branch main] [--need 30]
    python scripts/stress_streak.py --runs-file runs.json   # offline: a saved API page

It lists the scheduled runs of ``nightly-stress.yml`` on the branch and counts
consecutive green UTC days, ending at the most recent day with a finished run.
A day is green when its latest finished scheduled run concluded ``success``; a
day with no finished scheduled run, or whose latest run did not succeed, ends
the streak (a skipped night is not a green night). Manual
(``workflow_dispatch``) runs never count. ``GITHUB_TOKEN`` (or ``GH_TOKEN``)
is sent when set. Prints one JSON object; exit 0 when ``streak >= --need``,
1 when not, 2 when the API or the waiver file cannot be read.

Flake waivers (0.51, docs/RELEASING.md): ``docs/bench/stress-waivers.json``
lists nights whose failure was proven to be infrastructure, each a committed,
dated record naming its owner, the cause and the evidence. A waived night
neither counts towards nor breaks the streak. A waiver without a date, an
owner, a cause or evidence, or dated before the night it waives, is refused
(exit 2). ``--write PATH`` also stores the result as plain JSON (the committed
``docs/bench/nightly-streak.json``).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

WORKFLOW = "nightly-stress.yml"
WAIVERS = Path(__file__).resolve().parents[1] / "docs" / "bench" / "stress-waivers.json"
WAIVER_FIELDS = ("night", "recorded", "owner", "cause", "evidence")
API = "https://api.github.com"


def fetch_runs(repo: str, branch: str, pages: int = 3) -> list[dict[str, Any]]:
    """Scheduled runs of the workflow on *branch*, newest first (100 per page)."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    runs: list[dict[str, Any]] = []
    for page in range(1, pages + 1):
        url = (
            f"{API}/repos/{repo}/actions/workflows/{WORKFLOW}/runs"
            f"?event=schedule&branch={urllib.parse.quote(branch, safe='')}"
            f"&per_page=100&page={page}"
        )
        request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed https host
            batch = _runs(json.load(response))
        runs.extend(batch)
        if len(batch) < 100:
            break
    return runs


def _runs(data: Any) -> list[dict[str, Any]]:
    """The ``workflow_runs`` list of an API page; a page without one is an API error."""
    if isinstance(data, list):
        runs = data
    elif isinstance(data, dict) and isinstance(data.get("workflow_runs"), list):
        runs = data["workflow_runs"]
    else:
        message = data.get("message") if isinstance(data, dict) else None
        raise ValueError(f"not a workflow-runs page: {message or type(data).__name__}")
    if not all(isinstance(run, dict) for run in runs):
        raise ValueError("a workflow run is not an object")
    return runs


def _day(run: dict[str, Any]) -> date:
    stamp = run.get("run_started_at") or run["created_at"]
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).date()


def load_waivers(data: Any) -> dict[date, dict[str, Any]]:
    """Validated waivers by night; any malformed record refuses the whole file."""
    records = data.get("waivers") if isinstance(data, dict) else None
    if not isinstance(records, list):
        raise ValueError("waiver file: expected an object with a 'waivers' list")
    out: dict[date, dict[str, Any]] = {}
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            raise ValueError(f"waiver {i}: not an object")
        for field in WAIVER_FIELDS:
            if not isinstance(rec.get(field), str) or not rec[field].strip():
                raise ValueError(
                    f"waiver {i}: missing {field!r} (undated or unowned waivers are refused)"
                )
        night, recorded = date.fromisoformat(rec["night"]), date.fromisoformat(rec["recorded"])
        if recorded < night:
            raise ValueError(f"waiver {i}: recorded {recorded} before the night it waives")
        if night in out:
            raise ValueError(f"waiver {i}: {night} is waived twice")
        out[night] = rec
    return out


def streak(
    runs: list[dict[str, Any]],
    today: date | None = None,
    waivers: dict[date, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Consecutive green days ending at *today* (or yesterday, while today's run is pending).

    Without *today* the streak ends at the latest day with a finished scheduled
    run. With it, a workflow that stopped running is not reported as a live
    streak: the walk starts at *today* (or the day before, when today has no
    finished run yet), so stale green history counts zero.
    """
    waivers = waivers or {}
    latest: dict[date, dict[str, Any]] = {}
    for run in runs:
        if run.get("event", "schedule") != "schedule" or run.get("status") != "completed":
            continue
        day = _day(run)
        if day not in latest or _stamp(run) > _stamp(latest[day]):
            latest[day] = run
    if not latest:
        return {"streak": 0, "since": None, "through": None, "broken_by": None, "waived": []}
    through = day = max(latest)
    if today is not None:
        through = day = today if today in latest else today - timedelta(days=1)
    count, broken_by, waived, since = 0, None, [], None
    while True:
        run = latest.get(day)
        if day in waivers and (run is None or run.get("conclusion") != "success"):
            waived.append(day.isoformat())
            day -= timedelta(days=1)
            if day < min(latest):
                broken_by = {"day": day.isoformat(), "reason": "before the first recorded run"}
                break
            continue
        if run is None:
            broken_by = {"day": day.isoformat(), "reason": "no finished scheduled run"}
            break
        if run.get("conclusion") != "success":
            broken_by = {"day": day.isoformat(), "reason": str(run.get("conclusion")),
                         "url": run.get("html_url")}  # fmt: skip
            break
        count, since = count + 1, day
        day -= timedelta(days=1)
        if day < min(latest):
            broken_by = {"day": day.isoformat(), "reason": "before the first recorded run"}
            break
    return {"streak": count, "since": since and since.isoformat(), "through": through.isoformat(),
            "broken_by": broken_by, "waived": waived}  # fmt: skip


def _stamp(run: dict[str, Any]) -> str:
    return str(run.get("run_started_at") or run.get("created_at") or "")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report the nightly stress green streak.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--repo", help="OWNER/NAME on github.com")
    source.add_argument("--runs-file", help="A saved workflow-runs API response (offline)")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--need", type=int, default=30, help="Days the 1.0 criterion needs")
    parser.add_argument("--today", help="UTC date the streak must reach (default: now, UTC)")
    parser.add_argument("--waivers", type=Path, default=WAIVERS, help="Flake waiver records")
    parser.add_argument("--write", type=Path, help="Also store the result here (plain JSON)")
    args = parser.parse_args(argv)
    try:
        waivers = {}
        if args.waivers.is_file():
            waivers = load_waivers(json.loads(args.waivers.read_text("utf-8")))
        if args.runs_file:
            runs = _runs(json.loads(Path(args.runs_file).read_text("utf-8")))
        else:
            runs = fetch_runs(args.repo, args.branch)
        today = date.fromisoformat(args.today) if args.today else datetime.now(UTC).date()
        result = {"workflow": WORKFLOW, "branch": args.branch, "need": args.need}
        result.update(streak(runs, today, waivers))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        # HTTPError/URLError/timeouts are OSError; a rate-limit or error body, a
        # malformed run or a bad --today is not a streak of zero: exit 2.
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 2
    result["met"] = result["streak"] >= args.need
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.write:
        args.write.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if result["met"] else 1


if __name__ == "__main__":
    sys.exit(main())
