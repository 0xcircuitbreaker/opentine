"""``GET|PUT tombstones/<oid>``: the remote half of ``tine purge`` (0.46, ``caps.tombstones``).

``GET`` needs ``fetch`` in the tenant and answers the stored record, or the
same ``404 not found`` whether the oid was never purged, never existed or is
another tenant's (no oid-existence oracle). ``PUT`` stores a client-signed
``opentine.tombstone`` after its shape checks (the server holds no user key, so
it cannot and does not vouch for the signature, and it never signs one). When
the tenant still holds the blob, the ``PUT`` is a purge: it needs ``purge``
(admin-only under the reference role policy), refuses an object a hold reaches
(not only a held root), writes the record first and then deletes the bytes and
their index row, undoing the record if the delete fails. A pushed pack never
restores a tombstoned blob (``_pack_ingest``). Recording a tombstone for a blob
the tenant does not hold needs
``upload``: it is what ``tine push`` sends before a pack whose shallow
boundaries are purged blobs.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from opentine._signed_record import BLOB_OID
from opentine._tombstone import FIELDS
from opentine.remote import _tombstone_store

PREFIX = "tombstones/"


def _not_found(app: Any, sr: Any):
    return app._json_response(sr, "404 Not Found", {"error": "not found"})


def _refuse_held(service: Any, tenant: str, oid: str) -> None:
    """A legal hold covers everything its roots reach, not only the held oids themselves."""
    roots = getattr(service.objects, "held", lambda _t: set())(tenant)
    if not roots:
        return
    if oid in roots:
        raise PermissionError(f"{oid} is held")
    from opentine.remote._admin_graph import scan

    if oid in scan(service.objects, service.index, tenant).live(roots):
        raise PermissionError(f"{oid} is reachable from a hold")


def _delete(service: Any, tenant: str, oid: str) -> None:
    """Delete the bytes and drop the index row, as ``tine serve admin delete-objects`` does."""
    exclusive = getattr(service.index, "exclusive", None)
    if not callable(exclusive):
        service.objects.delete(tenant, oid)
        return
    from opentine.remote._admin_backend import forget

    with exclusive() as database:
        service.objects.delete(tenant, oid)
        forget(database, tenant, [oid])


def tombstone_routes(app: Any, identity, tenant: str, resource: str, method: str, environ, sr):
    service = app.service
    oid = unquote(resource[len(PREFIX) :])
    root = getattr(service.objects, "root", None)
    if method == "GET":
        service._authorize(identity, "fetch", tenant)
        record = (
            _tombstone_store.read(root, tenant, oid)
            if root is not None and BLOB_OID.fullmatch(oid)
            else None
        )
        if record is None:
            return _not_found(app, sr)
        service._audit(identity, tenant, "fetch", "ok", {"tombstone": oid})
        return app._json_response(sr, "200 OK", {"tombstone": record})
    if method != "PUT":
        return _not_found(app, sr)
    if root is None or not BLOB_OID.fullmatch(oid):
        service._authorize(identity, "upload", tenant)
        raise ValueError("tombstones are not stored here, or the oid is not a blob")
    held = service.objects.has(tenant, oid)
    service._authorize(identity, "purge" if held else "upload", tenant)
    record = app._json(environ, *FIELDS, "signature")
    if record.get("oid") != oid:
        raise ValueError("the tombstone names another oid")
    if held:
        _refuse_held(service, tenant, oid)
    stored = _tombstone_store.write(root, tenant, record)
    purged = False
    if held:
        try:
            _delete(service, tenant, oid)
            purged = True
        except BaseException:
            if stored:
                _tombstone_store.remove(root, tenant, oid)
            raise
    action = "purge" if held else "upload"
    service._audit(identity, tenant, action, "ok", {"tombstone": oid, "purged": purged})
    return app._json_response(sr, "201 Created", {"stored": stored, "purged": purged})


__all__ = ["PREFIX", "tombstone_routes"]
