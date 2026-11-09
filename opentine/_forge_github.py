"""GitHub: a check run through the Checks API, and one PR comment (0.48).

Credentials, least privilege first:

* **A GitHub App** (``--app-id``, ``--app-key-file``, ``--installation-id``):
  the App needs only ``Checks: write`` and, for ``--pr``, ``Pull requests:
  write``. The installation token is requested with exactly those permissions
  (``POST /app/installations/{id}/access_tokens``), so even an App granted
  more gets a token that cannot do anything else. The JWT lives 9 minutes.
* **A token in an environment variable** (``--token-env``, default
  ``GITHUB_TOKEN``): in GitHub Actions, the job's ``GITHUB_TOKEN`` with
  ``permissions: {checks: write, pull-requests: write}``. A fine-grained
  personal token cannot create check runs (GitHub allows only App tokens).

The check run is ``completed`` with the record's conclusion, its
``details_url`` is the bundle URL and each overlay range is a ``notice``
annotation: the blame overlay in the PR's "Files changed" view.
"""

from __future__ import annotations

import base64
import json
import re
import time
from pathlib import Path
from typing import Any

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

PERMISSIONS = {"checks": "write", "pull_requests": "write"}
_SLUG = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def app_jwt(app_id: str, key_pem: bytes, now: int | None = None) -> str:
    """An RS256 JWT for the App (``iat`` 60 s back for clock skew, ``exp`` 9 minutes on)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ForgeError("the GitHub App key is not an RSA private key")
    issued = int(time.time()) if now is None else now
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"iat": issued - 60, "exp": issued + 540, "iss": str(app_id)}
    body = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signed = key.sign(f"{header}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{body}.{_b64(signed)}"


def credentials(args: Any, session: Any, base: str) -> str:
    if not args.app_id:
        return token(args.token_env or "GITHUB_TOKEN")
    if not (args.app_key_file and args.installation_id):
        raise ForgeError("a GitHub App needs --app-key-file and --installation-id")
    jwt = app_jwt(args.app_id, Path(args.app_key_file).read_bytes())
    # Least privilege: only the permissions used, and only this one repository.
    wanted = dict(PERMISSIONS) if args.pr else {"checks": "write"}
    answer = session.post(
        f"{base}/app/installations/{int(args.installation_id)}/access_tokens",
        headers={"Authorization": f"Bearer {jwt}", "Accept": "application/vnd.github+json"},
        json={"permissions": wanted, "repositories": [args.repo_slug.split("/")[1]]},
    )
    found = expect(answer, "requesting an installation token")
    if not isinstance(found, dict) or not isinstance(found.get("token"), str):
        raise ForgeError("requesting an installation token failed: no token in the answer")
    return found["token"]


def annotations(record: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for row in record["overlay"]:
        run = f" (run {row['run'][:16]})" if row["run"] else ""
        out.append(
            {
                "path": row["path"],
                "start_line": row["start_line"],
                "end_line": row["end_line"],
                "annotation_level": "notice",
                "title": "AI-attributed lines",
                "message": f"Lines {row['start_line']}-{row['end_line']} were written by an "
                f"agent{run}; see the OpenTine check for its evidence.",
            }
        )
    return out


def plan(args: Any, record: dict[str, Any]) -> list[dict[str, Any]]:
    slug = args.repo_slug
    steps = [{"target": "check-run", "method": "POST", "path": f"/repos/{slug}/check-runs"}]
    if args.pr:
        path = f"/repos/{slug}/issues/{int(args.pr)}/comments"
        steps.append({"target": "comment", "method": "POST|PATCH", "path": path})
    return steps


def publish(args: Any, record: dict[str, Any], session: Any) -> list[dict[str, Any]]:
    slug = args.repo_slug or ""
    if not _SLUG.fullmatch(slug):
        raise ForgeError("GitHub needs --repo-slug OWNER/NAME (or GITHUB_REPOSITORY)")
    check_slug(slug, "GitHub")
    base = api_base(args.api_url or "https://api.github.com")
    secret = credentials(args, session, base)
    headers = {"Authorization": f"Bearer {secret}", "Accept": "application/vnd.github+json"}
    check = {
        "name": NAME,
        "head_sha": record["commit"],
        "status": "completed",
        "conclusion": record["conclusion"],
        "external_id": record["commit"],
        "output": {
            "title": title(record),
            "summary": summary(record),
            "annotations": annotations(record),
        },
    }
    if record["bundle"]["url"]:
        check["details_url"] = record["bundle"]["url"]
    made = expect(
        session.post(f"{base}/repos/{slug}/check-runs", headers=headers, json=check),
        "creating the check run",
    )
    rows = [
        {
            "target": "check-run",
            "state": "created",
            "id": made.get("id") if isinstance(made, dict) else None,
        }
    ]
    if args.pr:
        author = args.comment_author or ("" if args.app_id else "github-actions[bot]")
        if not author:
            raise ForgeError("an App's PR comment needs --comment-author APP-SLUG[bot]")

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


__all__ = ["PERMISSIONS", "annotations", "app_jwt", "credentials", "plan", "publish"]
