"""The remote half of ``tine review`` (0.47, ``caps.reviews``).

``push`` reads the remote's copy (``GET reviews/<id>``), refuses one that forks
from the local chain, sends each version it lacks with ``PUT reviews/<id>`` (a
compare-and-swap on the remote head) and then each decision it lacks with
``POST reviews/<id>/decisions``. The remote checks every record and stores it
as signed; it never signs one. A remote without ``caps.reviews`` is refused
before anything is sent.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from typing import Any
from urllib.parse import quote

from opentine._cli_remote_target import resolve, tenant_path


def push(args: argparse.Namespace, local: dict[str, Any] | None) -> dict[str, Any]:
    from opentine import _review
    from opentine.repository._http import client, request_json

    if local is None:
        raise KeyError(f"no review {args.review_id} here")
    base, tenant, token = resolve(args, args.remote)
    path = tenant_path(tenant, f"reviews/{quote(args.review_id, safe='')}")
    sent = {"versions": 0, "decisions": 0}
    with closing(
        client(base, token, allow_insecure=args.allow_insecure, timeout=args.timeout)
    ) as http:
        _, caps = request_json(http, "GET", "/v1/capabilities", max_seconds=args.timeout)
        if not isinstance(caps.get("reviews"), dict):
            raise ValueError("the remote does not serve reviews (no caps.reviews)")
        status, body = request_json(http, "GET", path, allowed=(200, 404), max_seconds=args.timeout)
        remote = body.get("bundle") if status == 200 else None
        theirs = [_review.digest(v) for v in (remote or {}).get("versions", [])]
        ours = [_review.digest(v) for v in local["versions"]]
        if ours[: len(theirs)] != theirs:
            raise ValueError("the remote's review history is not a prefix of this one")
        head = theirs[-1] if theirs else None
        for record in local["versions"][len(theirs) :]:
            status, body = request_json(http, "PUT", path, allowed=(200, 409),
                                        max_seconds=args.timeout,
                                        json={"expected_old": head, "version": record})  # fmt: skip
            if status == 409 or body.get("updated") is not True:
                raise ValueError("the remote's review moved meanwhile: fetch and retry")
            head, sent["versions"] = body.get("digest"), sent["versions"] + 1
        known = {_review.digest(d) for d in (remote or {}).get("decisions", [])}
        for record in local["decisions"]:
            if _review.digest(record) in known:
                continue
            request_json(http, "POST", f"{path}/decisions", allowed=(201,),
                         max_seconds=args.timeout, json={"decision": record})  # fmt: skip
            sent["decisions"] += 1
    return {**sent, "head": head}


__all__ = ["push"]
