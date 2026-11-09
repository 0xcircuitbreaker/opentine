"""GitLab and Forgejo/Gitea: a commit status, and one MR note or PR comment (0.48).

**GitLab** (``--api-url``, default ``CI_API_V4_URL`` or
``https://gitlab.com/api/v4``): ``POST /projects/:id/statuses/:sha`` and the
MR's notes. The project is addressed by its ``forge_repo_id`` (the numeric
project id, or the URL-encoded path). The token (``--token-env``, default
``OPENTINE_GITLAB_TOKEN``) is a project access token with the Developer role
and the ``api`` scope: GitLab has no narrower scope that can write a commit
status. Store it as a masked, protected CI/CD variable.

**Forgejo / Gitea** (``--api-url`` required, e.g. ``https://codeberg.org/api/v1``):
``POST /repos/{owner}/{repo}/statuses/{sha}`` and the PR's issue comments.
The token (``--token-env``, default ``OPENTINE_FORGEJO_TOKEN``) needs only
``write:repository`` (the status) and, for ``--pr``, ``write:issue``; with a
``read:user`` scope too, comments are matched to the token's own user, else
``--comment-author`` names it.

Neither status API has a "neutral": an unverified commit is GitLab
``skipped`` and Forgejo ``warning``, never a success.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from opentine._forge_post import (
    NAME,
    ForgeError,
    api_base,
    check_slug,
    expect,
    summary,
    title,
    token,
    upsert,
)

GITLAB_STATE = {"success": "success", "failure": "failed", "neutral": "skipped"}
FORGEJO_STATE = {"success": "success", "failure": "failure", "neutral": "warning"}
_SLUG = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def _gitlab_base(args: Any) -> str:
    return api_base(args.api_url or "https://gitlab.com/api/v4")


def _gitlab_project(record: dict[str, Any]) -> str:
    return quote(record["forge_repo_id"], safe="")


def plan(args: Any, record: dict[str, Any]) -> list[dict[str, Any]]:
    if args.forge == "gitlab":
        project = _gitlab_project(record)
        steps = [
            {
                "target": "status",
                "method": "POST",
                "path": f"/projects/{project}/statuses/{record['commit']}",
            }
        ]
        if args.mr:
            steps.append(
                {
                    "target": "comment",
                    "method": "POST|PUT",
                    "path": f"/projects/{project}/merge_requests/{int(args.mr)}/notes",
                }
            )
        return steps
    slug = args.repo_slug
    steps = [
        {"target": "status", "method": "POST", "path": f"/repos/{slug}/statuses/{record['commit']}"}
    ]
    if args.pr:
        steps.append(
            {
                "target": "comment",
                "method": "POST|PATCH",
                "path": f"/repos/{slug}/issues/{int(args.pr)}/comments",
            }
        )
    return steps


def _description(record: dict[str, Any]) -> str:
    return title(record).removeprefix("OpenTine: ")[:140]


def gitlab(args: Any, record: dict[str, Any], session: Any) -> list[dict[str, Any]]:
    base, project = _gitlab_base(args), _gitlab_project(record)
    headers = {"PRIVATE-TOKEN": token(args.token_env or "OPENTINE_GITLAB_TOKEN")}
    params = {
        "state": GITLAB_STATE[record["conclusion"]],
        "name": NAME,
        "description": _description(record),
    }
    if record["bundle"]["url"]:
        params["target_url"] = record["bundle"]["url"]
    url = f"{base}/projects/{project}/statuses/{record['commit']}"
    expect(session.post(url, headers=headers, json=params), "writing the commit status")
    rows = [{"target": "status", "state": "created", "id": None}]
    if args.mr:
        me = expect(session.get(f"{base}/user", headers=headers), "reading the token user")
        if not isinstance(me, dict) or "id" not in me:
            raise ForgeError("reading the token user failed: no id")
        listing = f"{base}/projects/{project}/merge_requests/{int(args.mr)}/notes"

        def mine(row: dict[str, Any]) -> bool:
            author = row.get("author")
            return isinstance(author, dict) and author.get("id") == me["id"]

        state = upsert(
            session,
            listing=listing,
            item=listing + "/{id}",
            verb="PUT",
            headers=headers,
            body=summary(record),
            mine=mine,
        )
        rows.append({"target": "comment", "state": state, "id": None})
    return rows


def _forgejo_author(args: Any, session: Any, base: str, headers: dict[str, str]) -> str:
    if args.comment_author:
        return args.comment_author
    me = expect(session.get(f"{base}/user", headers=headers), "reading the token user")
    if not isinstance(me, dict) or not isinstance(me.get("login"), str):
        raise ForgeError("reading the token user failed: no login")
    return me["login"]


def forgejo(args: Any, record: dict[str, Any], session: Any) -> list[dict[str, Any]]:
    slug = args.repo_slug or ""
    if not _SLUG.fullmatch(slug):
        raise ForgeError("Forgejo needs --repo-slug OWNER/NAME")
    if not args.api_url:
        raise ForgeError("Forgejo needs --api-url, e.g. https://codeberg.org/api/v1")
    check_slug(slug, "Forgejo")
    base = api_base(args.api_url)
    headers = {"Authorization": f"token {token(args.token_env or 'OPENTINE_FORGEJO_TOKEN')}"}
    status = {
        "state": FORGEJO_STATE[record["conclusion"]],
        "context": NAME,
        "description": _description(record),
    }
    if record["bundle"]["url"]:
        status["target_url"] = record["bundle"]["url"]
    url = f"{base}/repos/{slug}/statuses/{record['commit']}"
    expect(session.post(url, headers=headers, json=status), "writing the commit status")
    rows = [{"target": "status", "state": "created", "id": None}]
    if args.pr:
        author = _forgejo_author(args, session, base, headers)

        def mine(row: dict[str, Any]) -> bool:
            user = row.get("user")
            return isinstance(user, dict) and user.get("login") == author

        listing = f"{base}/repos/{slug}/issues/{int(args.pr)}/comments"
        state = upsert(
            session,
            listing=listing,
            item=f"{base}/repos/{slug}/issues/comments/{{id}}",
            verb="PATCH",
            headers=headers,
            body=summary(record),
            mine=mine,
        )
        rows.append({"target": "comment", "state": state, "id": None})
    return rows


__all__ = ["FORGEJO_STATE", "GITLAB_STATE", "forgejo", "gitlab", "plan"]
