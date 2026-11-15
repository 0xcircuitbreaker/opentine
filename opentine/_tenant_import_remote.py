"""``tine tenant import --remote``: all or nothing (0.52).

1. The export is checked and installed into a scratch repository offline
   (``_tenant_move.import_local``): a bad bundle or Review stops here.
2. The target must list ``caps.tenant_import``; its refs are read and a ref that
   already points elsewhere is refused before anything is sent.
3. **Stage**: the tombstones the pack needs, then one pack of every ref's
   closure, go up with the ordinary routes. Objects no ref reaches change
   nothing a reader sees (a later ``gc`` collects them if the import stops).
4. **Swap**: one ``POST import`` names every ref, Review and project version;
   the server checks them all, then makes them visible together or not at all
   (``opentine.remote._tenant_import_http``).

An interrupted import leaves the tenant unchanged; running it again finishes
it, and a completed import run again changes nothing.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

NO_IMPORT = ("the target does not offer an all-or-nothing import (caps.tenant_import, "
             "tine serve 0.52+); nothing was sent")  # fmt: skip


def _stage(repo: Any, http: Any, prefix: str, caps: dict, refs: dict[str, str],
           timeout: float) -> int:  # fmt: skip
    from opentine.repository import _pack4, _pack_peer, _tombstone_sync
    from opentine.repository._http import request_json
    from opentine.repository._pack_fit import fitted_pack
    from opentine.repository._upload_client import upload
    from opentine.repository.client import _upload_result

    wants = sorted(set(refs.values()))
    if not wants:
        return 0
    pack, missing = fitted_pack(repo, wants, [])
    _tombstone_sync.send(repo, http, request_json, prefix, caps, pack, timeout)
    pack = _pack_peer.for_peer(pack, caps)
    state = upload(http, prefix + "/packs", pack, chunk_size=4 * 1024 * 1024, timeout=timeout)
    objects, _ = _upload_result(state, expected_objects=len(missing),
                                expected_pack=_pack4.pack_digest(pack))  # fmt: skip
    return objects


def import_remote(
    source: Path, base: str, tenant: str, token: str | None, *, allow_insecure: bool = False,
    timeout: float = 120.0,
) -> dict[str, Any]:  # fmt: skip
    """Import an export folder into a ``tine serve`` tenant, all or nothing."""
    from opentine._tenant_move import _files, import_local
    from opentine.repository import Repo
    from opentine.repository._http import client, request_json

    prefix = f"/v1/tenants/{quote(tenant, safe='')}"
    with tempfile.TemporaryDirectory(prefix="tine-leave-") as scratch:
        repo = Repo.init(Path(scratch) / "repo")
        refs = import_local(source, repo)["refs"]  # Reviews go in the swap below
        reviews = _files(source)
        project = _files(source, "project")
        with client(base, token, allow_insecure=allow_insecure, timeout=timeout) as http:
            _, caps = request_json(http, "GET", "/v1/capabilities", max_seconds=timeout)
            if not isinstance(caps, dict) or not caps.get("tenant_import"):
                raise ValueError(NO_IMPORT)
            _, listed = request_json(http, "GET", prefix + "/refs", max_seconds=timeout)
            current = (listed or {}).get("refs") or {}
            for name, oid in sorted(refs.items()):
                if current.get(name) not in (None, oid):
                    raise ValueError(f"{name} already points elsewhere there "
                                     f"({current[name]}); nothing was imported")  # fmt: skip
            _stage(repo, http, prefix, caps, refs, timeout)
            status, body = request_json(
                http, "POST", prefix + "/import", allowed=(200, 409), max_seconds=timeout,
                json={"refs": refs, "reviews": reviews, "project": project},
            )  # fmt: skip
    if status == 409:
        reason = (body or {}).get("conflict") or "the target changed"
        raise ValueError(f"{reason}; nothing was imported")
    names = [value["versions"][0]["review_id"] for value in reviews]
    return {"refs": refs, "reviews": names}


__all__ = ["import_remote"]
