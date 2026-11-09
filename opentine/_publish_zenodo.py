"""``tine publish zenodo``: deposit a run bundle (and crates) on Zenodo (0.49).

The Zenodo REST deposit flow: create a deposition, PUT each file into its
bucket, set the metadata, and (only with ``--publish``) publish it, which mints
a DOI and cannot be undone. Without ``--publish`` the deposition stays a draft
the owner reviews on Zenodo. ``--sandbox`` targets ``sandbox.zenodo.org`` (its
own account and token). The token is read from ``ZENODO_TOKEN`` (or
``--token-env``) and sent only as a bearer header to the API host.
"""

from __future__ import annotations

from html import escape
from typing import Any

from opentine._publish_common import PublishError, expect, same_host

ZENODO = "https://zenodo.org/api"
SANDBOX = "https://sandbox.zenodo.org/api"
TOKEN_ENV = "ZENODO_TOKEN"
KEYWORDS = ["opentine", "agent run", "provenance"]


def metadata(args: Any, digest: str, refs: dict[str, str]) -> dict[str, Any]:
    creators = [name.strip() for name in args.creator if name.strip()]
    if not creators:
        raise ValueError("Zenodo needs at least one --creator NAME")
    title = args.title or f"OpenTine run bundle {digest.removeprefix('sha256:')[:12]}"
    listed = "".join(
        f"<li><code>{escape(ref)}</code>: <code>{escape(oid)}</code></li>"
        for ref, oid in refs.items()
    )
    description = args.description or (
        "An OpenTine run bundle. Verify it offline with <code>tine bundle verify FILE</code> "
        f"(bundle digest <code>{digest}</code>).<ul>{listed}</ul>"
    )
    return {
        "upload_type": "dataset",
        "title": title,
        "description": description,
        "creators": [{"name": name} for name in creators],
        "access_right": args.access_right,
        "license": args.license,
        "keywords": KEYWORDS,
        "notes": f"OpenTine bundle {digest}",
    }


def plan(files: list[tuple[str, bytes]], publish: bool) -> list[dict[str, str]]:
    steps = [{"method": "POST", "path": "/deposit/depositions"}]
    steps += [{"method": "PUT", "path": f"{{bucket}}/{name}"} for name, _data in files]
    steps.append({"method": "PUT", "path": "/deposit/depositions/{id}"})
    if publish:
        steps.append({"method": "POST", "path": "/deposit/depositions/{id}/actions/publish"})
    return steps


def deposit(
    session: Any,
    base: str,
    token: str,
    files: list[tuple[str, bytes]],
    meta: dict[str, Any],
    publish: bool,
) -> dict[str, Any]:
    """Run the deposit flow; returns ``{deposition, state, doi, url, files}``."""
    auth = {"Authorization": f"Bearer {token}"}
    made = expect(
        session.post(f"{base}/deposit/depositions", json={}, headers=auth), "create deposition"
    )
    if not isinstance(made, dict) or not isinstance(made.get("id"), int):
        raise PublishError("create deposition failed: the answer names no deposition id")
    ident, links = made["id"], made.get("links") or {}
    bucket = same_host(links.get("bucket"), base, "create deposition")
    uploaded = []
    for name, data in files:
        headers = {**auth, "Content-Type": "application/octet-stream"}
        answer = expect(session.put(f"{bucket}/{name}", content=data, headers=headers), "upload")
        checksum = answer.get("checksum") if isinstance(answer, dict) else None
        uploaded.append({"name": name, "bytes": len(data), "checksum": checksum})
    expect(
        session.put(f"{base}/deposit/depositions/{ident}", json={"metadata": meta}, headers=auth),
        "set metadata",
    )
    doi, url, state = None, links.get("html"), "draft"
    if publish:
        done = expect(
            session.post(f"{base}/deposit/depositions/{ident}/actions/publish", headers=auth),
            "publish",
            (200, 201, 202),
        )
        done = done if isinstance(done, dict) else {}
        doi, state = done.get("doi") or None, "published"
        url = (done.get("links") or {}).get("record_html") or (done.get("links") or {}).get("html")
    return {
        "deposition": ident,
        "state": state,
        "doi": doi if isinstance(doi, str) else None,
        "url": url if isinstance(url, str) and url.startswith("https://") else None,
        "files": uploaded,
    }


__all__ = ["SANDBOX", "TOKEN_ENV", "ZENODO", "deposit", "metadata", "plan"]
