"""Ref moves on the remote: one checked move, and ``POST ref-txn`` (0.43).

:func:`check_move` is every rule ``PUT /refs/<name>`` applies before its
compare-and-swap: the extra permission a namespace needs (``_ref_policy``), a
present object of the right type, a bound annotation ref, the fast-forward rule
on protected heads, and admission. ``POST /v1/tenants/<t>/ref-txn`` takes::

    {"updates": [{"name", "new", "expected_old"}, ...], "force": false}

checks every move the same way, then applies them **all or none** in one index
transaction (``IndexBackend.update_refs``): ``200 {"updated": true}``, or ``409
{"updated": false}`` with nothing changed when any ref was not at its expected
value. The server advertises ``"ref_txn": true`` in ``/v1/capabilities`` only
when its index can do this, and a client sends it only to such a server.
"""

from __future__ import annotations

from typing import Any

from opentine.kernel import parse_oid
from opentine.remote._ref_policy import FORCE, fast_forward_violation, ref_permission
from opentine.remote._tenant_repo import TenantRepo, admit_annotation_ref
from opentine.repository._refs import normalize_ref, validate_ref_target

#: At most this many refs move in one transaction.
MAX_TXN_UPDATES = 64


def check_move(
    service: Any,
    identity: Any,
    tenant: str,
    name: str,
    new_oid: str,
    expected_old: str | None,
    force: bool,
) -> tuple[str, bool]:
    """``(normalized name, whether it is a forced rewrite)``; raises when refused."""
    name = normalize_ref(name)
    extra = ref_permission(name, expected_old)
    if extra:  # promotions/*, or moving an existing tags/* ref (_ref_policy)
        service._authorize(identity, extra, tenant)
    parse_oid(new_oid)
    if expected_old is not None:
        parse_oid(expected_old)
    if not service.objects.has(tenant, new_oid):
        raise KeyError(new_oid)
    repo = TenantRepo(tenant, service.objects, service.index)
    target = repo.get(new_oid)
    validate_ref_target(name, target.object_type, target.payload())
    if target.object_type == "annotation":
        admit_annotation_ref(tenant, service.objects, service.index, name, target)
    rewrite = fast_forward_violation(
        repo, name, expected_old, new_oid, enabled=service.fast_forward_heads
    )
    if rewrite:  # a fast-forward-only head moved to an unrelated run (_ref_policy)
        if not force:
            service._audit(identity, tenant, "update_ref", "non-fast-forward", {"name": name})
            raise PermissionError("non-fast-forward update of a protected head")
        service._authorize(identity, FORCE, tenant)
    facts = {"name": name, "new": new_oid, "tenant": tenant}
    service.admission.admit(identity, "update_ref", facts)
    return name, rewrite


def supported(index: Any) -> bool:
    return callable(getattr(index, "update_refs", None))


def update_refs(
    service: Any, identity: Any, tenant: str, updates: Any, *, force: bool = False
) -> bool:
    service._authorize(identity, "update_ref", tenant)
    if not supported(service.index):
        raise ValueError("this server's index cannot apply ref transactions")
    if not isinstance(updates, list) or not 1 <= len(updates) <= MAX_TXN_UPDATES:
        raise ValueError(f"a ref transaction moves 1 to {MAX_TXN_UPDATES} refs")
    rows, moved, forced = [], [], False
    for update in updates:
        if not isinstance(update, dict) or set(update) - {"expected_old", "name", "new"}:
            raise ValueError("a ref transaction update is {name, new, expected_old}")
        new, old = update.get("new"), update.get("expected_old")
        if not isinstance(new, str) or not (old is None or isinstance(old, str)):
            raise ValueError("a ref transaction update needs a new oid")
        name, rewrite = check_move(service, identity, tenant, update.get("name"), new, old, force)
        rows.append((name, new, old))
        moved.append(rewrite)
        forced = forced or rewrite
    changed = service.index.update_refs(tenant, rows)
    outcome = ("forced" if forced else "ok") if changed else "conflict"
    names = [row[0] for row in rows]
    # name/new of the first (head) row: the 0.44 transparency entry a push receipt names
    head = {"name": rows[0][0], "new": rows[0][1]}
    service._audit(identity, tenant, "update_ref", outcome, {"names": names, "txn": True, **head})
    hub = getattr(service, "events", None)
    for (name, new, old), rewrite in zip(rows, moved) if changed and hub else ():
        hub.ref_moved(tenant, name, old, new, rewrite)
    return changed


def route(app: Any, identity: Any, tenant: str, environ: dict, start_response) -> Any:
    request = app._json(environ, "force", "updates")
    changed = update_refs(
        app.service, identity, tenant, request.get("updates"), force=request.get("force") is True
    )
    status = "200 OK" if changed else "409 Conflict"
    return app._json_response(start_response, status, {"updated": changed})


__all__ = ["MAX_TXN_UPDATES", "check_move", "route", "supported", "update_refs"]
