"""The read-only code API over a tenant's mirror (0.55, ``caps.project.mirror``).

``GET project/code/<read>`` with query parameters (a ref may hold slashes, so
it is never a path segment):

* ``refs``: every mirrored head and tag and the commit it names;
* ``tree?ref=&path=``: the entries of a directory;
* ``blob?ref=&path=``: a file as JSON (UTF-8 text, else base64; ``content``
  is null past ``max_blob_bytes``);
* ``raw?ref=&path=``: the file's bytes, labelled in ``X-OpenTine-*`` headers;
* ``history?ref=&path=&cursor=``: commits newest first, paged;
* ``compare?base=&head=``: commits in ``base..head`` and the files changed;
* ``search?q=``: code search (:mod:`._mirror_search`).

Every JSON answer carries ``mirror``: the upstream, the last-sync time and
``computed_by: "host"``, the label of a host statement (SPEC 4.17); the raw
bytes carry the same in headers. ``ref`` defaults to the slot's default
branch. An unknown ref, commit or path is the uniform ``404``.
"""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import parse_qs

from opentine import _mirror_git as gitio
from opentine.remote import _hosted_reads as reads
from opentine.remote import _mirror_store as store

_KEYS = {"ref", "path", "cursor", "base", "head", "q", "limit"}


def _query(environ) -> dict[str, str]:
    raw = str(environ.get("QUERY_STRING", ""))
    if len(raw) > 8192:
        raise ValueError("query string is too long")
    values = {key: found[-1] for key, found in parse_qs(raw).items()}
    if set(values) - _KEYS:
        raise ValueError("unknown query parameter")
    return values


def _number(value: str | None, default: int, top: int) -> int:
    if value is None:
        return default
    if not value.isdigit() or len(value) > 7:
        raise ValueError("cursor and limit are numbers")
    return min(int(value), top)


def _text(data: bytes) -> tuple[str, str]:
    try:
        return "utf-8", data.decode("utf-8")
    except UnicodeDecodeError:
        return "base64", base64.b64encode(data).decode("ascii")


def _raw(sr, data: bytes, mirror: dict[str, Any]):
    headers = [
        ("Content-Length", str(len(data))),
        ("Content-Type", "application/octet-stream"),
        ("X-Content-Type-Options", "nosniff"),
        ("Content-Security-Policy", "sandbox"),
        ("Cache-Control", "no-store"),
        ("X-OpenTine-Upstream", mirror["upstream"]),
        ("X-OpenTine-Synced-At", mirror["synced_at"] or ""),
        ("X-OpenTine-Computed-By", mirror["computed_by"]),
    ]
    sr("200 OK", headers)
    return [data]


def _read(repo, cfg, linked, read: str, q: dict[str, str], root, tenant) -> Any:
    page = cfg["max_page"]
    if read == "refs":
        refs = gitio.refs(repo)
        return {"refs": refs, "default_branch": linked["default_branch"]}
    if read == "search":
        from opentine.remote import _mirror_search

        return _mirror_search.search(root, tenant, q.get("q", ""), _number(q.get("limit"), 20, 50))
    if read == "compare":
        base, head = gitio.resolve(repo, q.get("base", "")), gitio.resolve(repo, q.get("head", ""))
        return {"base": base, "head": head, **gitio.compare(repo, base, head, page)}
    ref = q.get("ref") or linked["default_branch"]
    commit = gitio.resolve(repo, ref)
    path = gitio.checked_path(q.get("path", ""))
    common = {"ref": ref, "commit": commit, "path": path}
    if read == "tree":
        return {**common, "entries": gitio.tree(repo, commit, path)}
    if read == "history":
        cursor = _number(q.get("cursor"), 0, 10_000_000)
        commits = gitio.history(repo, commit, path, cursor, page + 1)
        following = cursor + page if len(commits) > page else None
        return {**common, "commits": commits[:page], "next_cursor": following}
    if read in ("blob", "raw"):
        oid, data, size = gitio.blob(repo, commit, path, cfg["max_blob_bytes"])
        if read == "raw":
            if data is None:
                raise PermissionError("mirror.limit-exceeded")
            return data
        encoding, content = _text(data) if data is not None else (None, None)
        return {**common, "oid": oid, "size": size, "encoding": encoding, "content": content,
                "truncated": data is None}  # fmt: skip
    raise reads.Hidden(read)


def code_read(app, tenant: str, root, cfg, read: str, environ, sr, mirror: dict[str, Any]):
    """Answer one code read; the caller has already checked the tenant is readable."""
    linked = store.link_of(root, tenant)
    state = store.state_of(root, tenant)
    repo = store.repo(root, tenant)
    if (
        linked is None
        or state is None
        or state["status"] == "paused"
        or not (repo / "HEAD").is_file()
    ):
        raise reads.Hidden("not synced")
    try:
        found = _read(repo, cfg, linked, read, _query(environ), root, tenant)
    except gitio.Missing as exc:
        raise reads.Hidden("missing") from exc
    except PermissionError:
        body = {
            "error": "the file is larger than the mirror serves",
            "code": "mirror.limit-exceeded",
        }
        return app._json_response(sr, "403 Forbidden", body)
    except gitio.GitError as exc:
        raise reads.Hidden("unreadable") from exc
    if isinstance(found, bytes):
        return _raw(sr, found, mirror)
    return app._json_response(sr, "200 OK", {**found, "mirror": mirror})


__all__ = ["code_read"]
