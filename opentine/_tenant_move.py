"""Leave the hosted service: export a ``tine serve`` tenant, import it elsewhere (0.50).

Nothing here is a new format. An export directory holds only files whose
formats were frozen at 0.48:

* ``tenant.tbundle`` -- an ``opentine-bundle`` (SPEC 8.6) of every tenant ref
  whose closure the server holds, with the tombstones of purged blobs and any
  ``tine-sig/3`` sidecars it carries;
* ``reviews/<id>.json`` -- each Review as its ``opentine-review-bundle-1``
  (versions and gate decisions, exactly as their reviewers signed them);
* ``log/checkpoint.json`` and ``log/entries.json`` -- the server's signed
  transparency-log checkpoint and this tenant's entries, as ``GET
  transparency/checkpoint`` and ``GET log/entries`` returned them;
* ``project/<seq>.json`` -- every ``opentine-project-1`` manifest version,
  oldest first, as its owner signed it;
* ``shares.json`` -- share-link metadata as ``GET shares`` returned it (ids,
  runs, expiry; never a token).

Import reads the bundle, the Reviews and (into a remote) the project manifests.
The log stays the old server's signed history (a new server keeps its own
log); share links are capabilities minted by the old server and are re-created
on the new one by hand.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

from opentine._review_rules import ID
from opentine.kernel import canonical_json

BUNDLE = "tenant.tbundle"
MAX_LOG_PAGES = 10_000


def _get(http: Any, path: str, timeout: float, **kwargs: Any) -> dict[str, Any] | None:
    from opentine.repository._http import request_json

    status, body = request_json(http, "GET", path, allowed=(200, 404), max_seconds=timeout,
                                **kwargs)  # fmt: skip
    return body if status == 200 else None


def _write(path: Path, value: Any) -> None:
    from opentine.repository.store import _atomic_bytes

    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_bytes(path, canonical_json(value) + b"\n")


def _log(http: Any, prefix: str, timeout: float) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(MAX_LOG_PAGES):
        params = {"limit": "500", **({"cursor": cursor} if cursor else {})}
        page = _get(http, prefix + "/log/entries", timeout, params=params)
        if page is None:
            break
        items.extend(page.get("items") or [])
        cursor = page.get("next_cursor")
        if not cursor:
            break
    return items


def _project(http: Any, prefix: str, timeout: float) -> list[dict[str, Any]]:
    versions: list[dict[str, Any]] = []
    cursor: int | None = 0
    for _ in range(MAX_LOG_PAGES):
        params = {"cursor": str(cursor)} if cursor else None
        page = _get(http, prefix + "/project/history", timeout, params=params)
        if page is None:
            break
        versions.extend(page.get("versions") or [])
        cursor = page.get("next_cursor")
        if not isinstance(cursor, int):
            break
    return versions


def export(
    base: str, tenant: str, token: str | None, out: Path, *, allow_insecure: bool = False,
    timeout: float = 120.0,
) -> dict[str, Any]:  # fmt: skip
    """Write everything *tenant* holds on *base* that leaves in a frozen format to *out*."""
    from opentine import _bundle
    from opentine.repository import Repo
    from opentine.repository._http import client
    from opentine.repository.client import fetch

    out.mkdir(parents=True, exist_ok=True)
    prefix = f"/v1/tenants/{quote(tenant, safe='')}"
    with client(base, token, allow_insecure=allow_insecure, timeout=timeout) as http:
        caps = _get(http, "/v1/capabilities", timeout) or {}
        refs = dict(sorted(((_get(http, prefix + "/refs", timeout) or {}).get("refs") or {})
                           .items()))  # fmt: skip
        reviews = []
        if caps.get("reviews"):
            for row in (_get(http, prefix + "/reviews", timeout) or {}).get("reviews") or []:
                name = str(row.get("review_id"))
                if not ID.fullmatch(name):  # it becomes a file name
                    raise ValueError(f"the remote lists an invalid review id: {name!r}")
                body = _get(http, f"{prefix}/reviews/{name}", timeout)
                if body is not None:
                    _write(out / "reviews" / f"{name}.json", body["bundle"])
                    reviews.append(name)
        project = _project(http, prefix, timeout) if caps.get("project") else []
        for seq, version in enumerate(project):
            _write(out / "project" / f"{seq:06d}.json", version)
        checkpoint = _get(http, prefix + "/transparency/checkpoint", timeout)
        entries = _log(http, prefix, timeout) if caps.get("log_http") else []
        shares = (_get(http, prefix + "/shares", timeout) or {}) if caps.get("share") else {}
    if checkpoint is not None or entries:
        _write(out / "log" / "checkpoint.json", checkpoint)
        _write(out / "log" / "entries.json", {"items": entries})
    if shares:
        _write(out / "shares.json", shares)
    carried: dict[str, str] = {}
    skipped: list[str] = []
    with tempfile.TemporaryDirectory(prefix="tine-leave-") as scratch:
        repo = Repo.init(Path(scratch) / "repo")
        wants = sorted({oid for oid in refs.values() if ":" in oid})
        if wants:
            fetch(repo, base, tenant=tenant, token=token, wants=wants, remote_name="leave",
                  allow_insecure=allow_insecure, timeout=timeout)  # fmt: skip
        for name, oid in refs.items():
            (carried.__setitem__(name, oid) if repo.has(oid) else skipped.append(name))
        if carried:
            data = _bundle.create_refs(repo, carried)
            (out / BUNDLE).write_bytes(data)
    return {
        "command": "tenant-export",
        "tenant": tenant,
        "out": out.as_posix(),
        "refs": carried,
        "skipped_refs": skipped,
        "reviews": reviews,
        "project_versions": len(project),
        "log_entries": len(entries),
        "shares": len(shares.get("shares") or []),
        "bundle": BUNDLE if carried else None,
    }


def _files(source: Path, folder_name: str = "reviews") -> list[dict[str, Any]]:
    folder = source / folder_name
    files = sorted(folder.glob("*.json")) if folder.is_dir() else []
    return [json.loads(path.read_text("utf-8")) for path in files]


def import_local(source: Path, repo: Any) -> dict[str, Any]:
    """Install an export into *repo*: the same ref names, every Review."""
    from opentine import _bundle, _bundle_extra, _bundle_sigs
    from opentine.repository import _review_store

    refs: dict[str, str] = {}
    if (source / BUNDLE).exists():
        checked = _bundle.verify(_bundle.read_file(source / BUNDLE))
        repo.import_pack(checked.pack)
        local = repo.list_refs()
        rows = []
        for name, oid in sorted(checked.refs.items()):
            old = local.get(name)
            if old is not None and old != oid:
                raise ValueError(f"{name} already points elsewhere here ({old}); not overwritten")
            if old is None:
                rows.append((name, oid, None))
        if rows:
            repo.update_refs(rows, actor="tenant-import")
        _bundle_sigs.install(repo, checked.signatures)
        _bundle_extra.install(repo, checked.tombstones)
        refs = checked.refs
    reviews = []
    for value in _files(source):
        _review_store.install(repo, value)
        reviews.append(value["versions"][0]["review_id"])
    return {"refs": refs, "reviews": reviews}


def import_remote(
    source: Path, base: str, tenant: str, token: str | None, *, allow_insecure: bool = False,
    timeout: float = 120.0,
) -> dict[str, Any]:  # fmt: skip
    """Push an export to a ``tine serve`` tenant: refs, tombstones and Reviews."""
    from opentine import _project as _project_record
    from opentine import _review
    from opentine.repository import Repo
    from opentine.repository._http import client, request_json
    from opentine.repository.client import push

    with tempfile.TemporaryDirectory(prefix="tine-leave-") as scratch:
        repo = Repo.init(Path(scratch) / "repo")
        refs = import_local(source, repo)["refs"]  # Reviews go over HTTP below
        for name in sorted(refs, key=lambda n: (n.startswith("annotations/"), n)):
            push(repo, base, tenant=tenant, token=token, ref=name, remote_ref=name,
                 allow_insecure=allow_insecure, timeout=timeout)  # fmt: skip
    prefix = f"/v1/tenants/{quote(tenant, safe='')}/reviews/"
    reviews = []
    with client(base, token, allow_insecure=allow_insecure, timeout=timeout) as http:
        for value in _files(source):
            review_id = value["versions"][0]["review_id"]
            path = prefix + quote(review_id, safe="")
            head = None
            for version in value["versions"]:
                request_json(http, "PUT", path, json={"expected_old": head, "version": version},
                             max_seconds=timeout)  # fmt: skip
                head = _review.digest(version)
            for decision in value.get("decisions") or []:
                request_json(http, "POST", path + "/decisions", json={"decision": decision},
                             allowed=(201,), max_seconds=timeout)  # fmt: skip
            reviews.append(review_id)
        head = None
        for manifest in _files(source, "project"):  # the manifest names its tenant
            request_json(http, "PUT", f"/v1/tenants/{quote(tenant, safe='')}/project",
                         json={"expected_old": head, "manifest": manifest},
                         max_seconds=timeout)  # fmt: skip
            head = _project_record.digest(manifest)
    return {"refs": refs, "reviews": reviews}


__all__ = ["BUNDLE", "export", "import_local", "import_remote"]
