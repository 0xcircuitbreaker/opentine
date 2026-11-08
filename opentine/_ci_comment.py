"""Post or update the gate's one PR/MR comment (0.46, ``actions/gate`` and GitLab).

``python -m opentine._ci_comment github|gitlab --body comment.md`` finds the
comment that carries :data:`opentine._ci_gate.MARKER` and edits it, else
creates one, so a pipeline re-run never stacks comments. Everything it needs
comes from the CI environment:

* GitHub: ``GITHUB_TOKEN`` (``pull-requests: write`` is the only permission it
  uses), ``GITHUB_REPOSITORY``, ``OPENTINE_PR`` (the PR number) and
  ``GITHUB_API_URL``.
* GitLab: ``OPENTINE_GITLAB_TOKEN`` (a project access token with ``api``
  scope, stored as a masked variable), ``CI_PROJECT_ID``,
  ``CI_MERGE_REQUEST_IID`` and ``CI_API_V4_URL``.

The token is sent only in a request header to that API host. It is never
printed: a failure reports the HTTP status and nothing else.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import httpx

from opentine._ci_gate import MARKER

MAX_BODY = 60_000


def _github(env: dict[str, str]) -> tuple[str, dict[str, str], str, str]:
    base = env.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    repo, number = env["GITHUB_REPOSITORY"], env["OPENTINE_PR"]
    headers = {"Authorization": f"Bearer {env['GITHUB_TOKEN']}",
               "Accept": "application/vnd.github+json"}  # fmt: skip
    listing = f"{base}/repos/{repo}/issues/{int(number)}/comments"
    return listing, headers, f"{base}/repos/{repo}/issues/comments/{{id}}", "PATCH"


def _gitlab(env: dict[str, str]) -> tuple[str, dict[str, str], str, str]:
    base = env.get("CI_API_V4_URL", "https://gitlab.com/api/v4").rstrip("/")
    project, iid = env["CI_PROJECT_ID"], env["CI_MERGE_REQUEST_IID"]
    headers = {"PRIVATE-TOKEN": env["OPENTINE_GITLAB_TOKEN"]}
    listing = f"{base}/projects/{int(project)}/merge_requests/{int(iid)}/notes"
    return listing, headers, listing + "/{id}", "PUT"


PROVIDERS = {"github": _github, "gitlab": _gitlab}


def upsert(provider: str, body: str, env: dict[str, str], client: httpx.Client) -> str:
    """``created`` or ``updated``; raises ``RuntimeError`` naming only the HTTP status."""
    listing, headers, item, verb = PROVIDERS[provider](env)
    if MARKER not in body:
        body = MARKER + "\n" + body
    body = body[:MAX_BODY]
    found = client.get(listing, headers=headers, params={"per_page": 100})
    if found.status_code != 200:
        raise RuntimeError(f"listing comments failed: HTTP {found.status_code}")
    rows: Any = found.json()
    mine = [row for row in rows if isinstance(row, dict) and MARKER in str(row.get("body", ""))]
    if mine:
        answer = client.request(verb, item.format(id=int(mine[0]["id"])), headers=headers,
                                json={"body": body})  # fmt: skip
        state = "updated"
    else:
        answer = client.post(listing, headers=headers, json={"body": body})
        state = "created"
    if answer.status_code not in (200, 201):
        raise RuntimeError(f"writing the comment failed: HTTP {answer.status_code}")
    return state


def main(argv: list[str] | None = None, client: httpx.Client | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m opentine._ci_comment")
    p.add_argument("provider", choices=sorted(PROVIDERS))
    p.add_argument("--body", required=True, metavar="FILE")
    args = p.parse_args(argv)
    body = Path(args.body).read_text(encoding="utf-8")
    try:
        with client or httpx.Client(timeout=30, follow_redirects=False) as session:
            print(f"opentine gate comment {upsert(args.provider, body, dict(os.environ), session)}")
    except KeyError as exc:
        print(f"opentine gate comment skipped: {exc.args[0]} is not set", file=sys.stderr)
        return 0
    except (RuntimeError, ValueError, httpx.HTTPError) as exc:
        message = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print(f"opentine gate comment: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
