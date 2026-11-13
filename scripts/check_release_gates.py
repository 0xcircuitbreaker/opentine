#!/usr/bin/env python3
"""Release-gate checklist: is every standing 1.0 gate green for one commit?

    python scripts/check_release_gates.py SHA [--repo OWNER/NAME] [--need 30]
    python scripts/check_release_gates.py SHA --recorded responses.json   # offline

Reads the GitHub Actions API through the ``gh`` CLI (``gh api``), so it uses
whatever ``gh auth`` holds. Without ``gh`` it prints why it skipped and exits 0
(exit 3 with ``--require``): the checklist is never required offline.

Gates (docs/RELEASING.md "Standing release gates"):

* ``parity``, ``peer-compat``, ``audit-kit``, ``leave-service``: the named jobs
  of ``ci.yml``'s push run for the commit, every matrix leg ``success``;
* ``bench``: the criterion-6 job of ``bench.yml``'s run for the commit;
* ``nightly-streak``: ``scripts/stress_streak.py`` over the scheduled
  ``nightly-stress.yml`` runs, with the committed flake waivers, ``>= --need``.

Prints one JSON object; exit 0 when every gate is green, 1 when any is not,
2 when the API cannot be read.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPO = "0xcircuitbreaker/opentine"

#: gate -> (workflow file, job-name prefix); every matching job must succeed.
JOB_GATES: dict[str, tuple[str, str]] = {
    "parity": ("ci.yml", "Python / TS / pyz vector parity"),
    "peer-compat": ("ci.yml", "0.34 peer compatibility"),
    "audit-kit": ("ci.yml", "Audit kit offline"),
    "leave-service": ("ci.yml", "Leave the hosted service"),
    "bench": ("bench.yml", "Bench (ubuntu-24.04, single-threaded)"),
}

Api = Callable[[str], Any]


def gh_api(path: str) -> Any:
    """``gh api PATH`` as JSON; raises OSError when the call fails."""
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["gh", "api", "-H", "Accept: application/vnd.github+json", path],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        raise OSError(f"gh api {path}: {proc.stderr.strip() or proc.returncode}")
    return json.loads(proc.stdout)


def recorded_api(responses: dict[str, Any]) -> Api:
    """An API backed by saved responses keyed by request path (offline tests)."""

    def call(path: str) -> Any:
        if path not in responses:
            raise OSError(f"no recorded response for {path}")
        return responses[path]

    return call


def _streak_module():
    spec = importlib.util.spec_from_file_location(
        "_stress_streak", ROOT / "scripts" / "stress_streak.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def job_gate(api: Api, repo: str, sha: str, workflow: str, prefix: str) -> dict[str, Any]:
    page = api(f"repos/{repo}/actions/workflows/{workflow}/runs?head_sha={sha}&per_page=100")
    runs = [r for r in page.get("workflow_runs", []) if r.get("head_sha") == sha]
    if not runs:
        return {"status": "missing", "detail": f"no {workflow} run for {sha[:12]}"}
    run = max(runs, key=lambda r: (r.get("run_attempt", 1), r.get("created_at", "")))
    jobs = api(f"repos/{repo}/actions/runs/{run['id']}/jobs?per_page=100").get("jobs", [])
    mine = [j for j in jobs if str(j.get("name", "")).startswith(prefix)]
    detail = {"run": run.get("html_url"), "jobs": len(mine)}
    if not mine:
        return {"status": "missing", "detail": f"no job named {prefix!r} in {workflow}", **detail}
    if any(j.get("status") != "completed" for j in mine):
        return {"status": "pending", **detail}
    bad = sorted(j["name"] for j in mine if j.get("conclusion") != "success")
    if bad:
        return {"status": "red", "failed": bad, **detail}
    return {"status": "green", **detail}


def streak_gate(api: Api, repo: str, need: int, today: date) -> dict[str, Any]:
    module = _streak_module()
    page = api(
        f"repos/{repo}/actions/workflows/{module.WORKFLOW}/runs?event=schedule&branch=main&per_page=100"
    )
    waivers = {}
    if module.WAIVERS.is_file():
        waivers = module.load_waivers(json.loads(module.WAIVERS.read_text("utf-8")))
    got = module.streak(module._runs(page), today, waivers)
    status = "green" if got["streak"] >= need else "red"
    return {"status": status, "streak": got["streak"], "need": need, "waived": got["waived"]}


def check(api: Api, repo: str, sha: str, need: int, today: date) -> dict[str, Any]:
    gates = {name: job_gate(api, repo, sha, *spec) for name, spec in JOB_GATES.items()}
    gates["nightly-streak"] = streak_gate(api, repo, need, today)
    green = all(g["status"] == "green" for g in gates.values())
    return {"sha": sha, "repo": repo, "gates": gates, "all_green": green}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the standing 1.0 release gates for a commit."
    )
    parser.add_argument("sha", help="The full commit SHA being released")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="OWNER/NAME on github.com")
    parser.add_argument("--need", type=int, default=30, help="Green nightly days required")
    parser.add_argument("--today", help="UTC date for the streak (default: now)")
    parser.add_argument("--recorded", type=Path, help="Saved API responses keyed by path")
    parser.add_argument("--require", action="store_true", help="Exit 3 instead of 0 when skipped")
    args = parser.parse_args(argv)
    if args.recorded:
        api = recorded_api(json.loads(args.recorded.read_text("utf-8")))
    elif shutil.which("gh") is None:
        print(json.dumps({"skipped": True, "reason": "the gh CLI is not installed; "
                          "install it and run `gh auth login` to read the gates"}))  # fmt: skip
        return 3 if args.require else 0
    else:
        api = gh_api
    try:
        today = date.fromisoformat(args.today) if args.today else datetime.now(UTC).date()
        result = check(api, args.repo, args.sha, args.need, today)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["all_green"] else 1


if __name__ == "__main__":
    sys.exit(main())
