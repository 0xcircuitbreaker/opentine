"""The remote half of ``tine project`` (0.46.1, ``caps.project``).

``remote_history`` pages ``GET project/history`` and refuses a remote whose
project is not the one ``tine remote add --project ID`` pinned. ``push`` sends
each local version the remote lacks with ``PUT project`` (a compare-and-swap
on the remote's head digest); the remote checks the chain and the owner's
signature and stores the manifest as signed, it never signs one. A remote
without ``caps.project`` is refused before anything is sent.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from typing import Any

from opentine._cli_remote_target import entry_for, resolve, tenant_path

MAX_PAGES = 100


def _pinned(args: argparse.Namespace) -> str | None:
    target = args.remote or "origin"
    if "://" in target:
        return None
    return (entry_for(args.repo, target) or {}).get("project")


def _session(args: argparse.Namespace):
    from opentine.repository._http import client, request_json

    base, tenant, token = resolve(args, args.remote)
    http = client(base, token, allow_insecure=args.allow_insecure, timeout=args.timeout)
    _, caps = request_json(http, "GET", "/v1/capabilities", max_seconds=args.timeout)
    if not isinstance(caps.get("project"), dict):
        http.close()
        raise ValueError("the remote does not serve projects (no caps.project)")
    return http, tenant, request_json


def _history(args: argparse.Namespace, http, tenant: str, request_json) -> list[dict[str, Any]]:
    versions: list[dict[str, Any]] = []
    cursor: int | None = 0
    for _ in range(MAX_PAGES):
        params = {"cursor": str(cursor)} if cursor else None
        status, body = request_json(http, "GET", tenant_path(tenant, "project/history"),
                                    allowed=(200, 404), max_seconds=args.timeout,
                                    params=params)  # fmt: skip
        if status == 404:
            return []
        versions.extend(body.get("versions") or [])
        cursor = body.get("next_cursor")
        if not isinstance(cursor, int):
            break
    pinned = _pinned(args)
    if pinned and versions and versions[0].get("project_id") != pinned:
        raise ValueError(f"the remote serves project {versions[0].get('project_id')!r}, "
                         f"not the pinned {pinned!r}")  # fmt: skip
    return versions


def remote_history(args: argparse.Namespace) -> list[dict[str, Any]]:
    http, tenant, request_json = _session(args)
    with closing(http):
        versions = _history(args, http, tenant, request_json)
    if not versions:
        raise KeyError("not found (or not visible to this token)")
    return versions


def push(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _project
    from opentine.repository import Repo, _project_ref

    local = _project_ref.history(Repo.open(args.repo))
    if not local:
        raise KeyError("no project here: `tine project init` first")
    pinned = _pinned(args)
    if pinned and local[0]["project_id"] != pinned:
        raise ValueError(f"this repository's project is not the remote's pinned {pinned!r}")
    http, tenant, request_json = _session(args)
    sent = 0
    with closing(http):
        remote = _history(args, http, tenant, request_json)
        digests = [_project.digest(record) for record in local]
        if remote and _project.digest(remote[-1]) not in digests:
            raise ValueError("the remote's project history is not a prefix of this one")
        head = _project.digest(remote[-1]) if remote else None
        for record in local[len(remote) :]:
            status, body = request_json(
                http,
                "PUT",
                tenant_path(tenant, "project"),
                allowed=(200, 409),
                max_seconds=args.timeout,
                json={"expected_old": head, "manifest": record},
            )
            if status == 409 or body.get("updated") is not True:
                raise ValueError("the remote's project moved meanwhile: fetch and retry")
            head, sent = body.get("digest"), sent + 1
    return {"sent": sent, "head": head, "versions": len(local)}


__all__ = ["push", "remote_history"]
