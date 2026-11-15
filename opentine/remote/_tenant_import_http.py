"""``POST /v1/tenants/<t>/import`` (0.52, ``caps.tenant_import``): an all-or-nothing import.

``tine tenant import --remote`` first uploads the export's objects (and the
tombstones its packs need) with the ordinary pack route -- unreachable objects
move no ref and change nothing a reader sees -- then sends one request::

    {"refs": {name: oid}, "reviews": [opentine-review-bundle-1, ...],
     "project": [opentine-project-1, ...]}

Everything is checked before anything is written: each ref as ``PUT refs``
checks it (``_ref_txn.check_move``), each Review version chain and gate
decision, and the project chain (its tenant must be this one). A ref that
already points elsewhere, a Review or project that already exists with other
content, answers ``409 {"imported": false, "conflict": ...}`` with nothing
changed; what already matches is skipped, so a repeated import is a no-op.
Then ``_tenant_import_apply`` stages, commits (the refs move in one index
transaction) or recovers: the tenant ends unchanged or fully imported.
``update_ref`` permission; ``200 {"imported": true, "refs", "reviews",
"project_versions"}`` counts what was added. One import per server at a time.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from opentine import _project, _review
from opentine._review_rules import gate_body
from opentine._signed_record import RecordError
from opentine.remote import _hosted_reads as reads
from opentine.remote import _project_store, _review_store
from opentine.remote import _tenant_import_apply as apply
from opentine.remote._ref_txn import check_move, supported
from opentine.repository._refs import normalize_ref

MAX_REFS = 10_000
MAX_REVIEWS = 1_000
_LOCK = threading.Lock()


class Conflict(ValueError):
    """The target already holds something else under a name the import uses."""


@dataclass
class Plan:
    rows: list[tuple[str, str]] = field(default_factory=list)
    reviews: list[tuple[str, list[dict], list[dict]]] = field(default_factory=list)
    project: list[dict[str, Any]] = field(default_factory=list)


def capabilities(service: Any) -> dict[str, Any]:
    if getattr(service.objects, "root", None) is None or not supported(service.index):
        return {}
    return {"tenant_import": {"path": "import", "max_refs": MAX_REFS,
                              "max_reviews": MAX_REVIEWS}}  # fmt: skip


def _refs(service, identity, tenant: str, refs: Any, plan: Plan) -> None:
    if not isinstance(refs, dict) or len(refs) > MAX_REFS:
        raise ValueError(f"refs is an object of at most {MAX_REFS} name: oid pairs")
    current = service.index.list_refs(tenant)
    for name, oid in sorted(refs.items()):
        if not isinstance(oid, str):
            raise ValueError("a ref names an oid")
        have = current.get(normalize_ref(name))
        if have == oid:
            continue
        if have is not None:
            raise Conflict(f"{name} already points elsewhere here ({have})")
        moved, _ = check_move(service, identity, tenant, name, oid, None, False)
        plan.rows.append((moved, oid))


def _chain(versions: Any, check: Any, code: str) -> None:
    if not isinstance(versions, list) or not versions:
        raise RecordError(f"{code}.malformed", f"{code} has no versions")
    previous = None
    for version in versions:
        found = check(version, previous=previous)
        if previous is None and found["seq"] != 0:
            raise RecordError(f"{code}.chain-break", "the first version stored must be seq 0")
        previous = version


def _reviews(root, tenant: str, bundles: Any, plan: Plan) -> None:
    if not isinstance(bundles, list) or len(bundles) > MAX_REVIEWS:
        raise ValueError(f"reviews is a list of at most {MAX_REVIEWS} review bundles")
    seen: set[str] = set()
    for bundle in bundles:
        versions = bundle.get("versions") if isinstance(bundle, dict) else None
        _chain(versions, _review.check, "review")
        review_id = versions[0]["review_id"]
        if any(v["review_id"] != review_id for v in versions) or review_id in seen:
            raise RecordError("review.malformed", "a review bundle mixes or repeats review ids")
        seen.add(review_id)
        by_digest = {_review.digest(v): v for v in versions}
        decisions, digests = [], set()
        for decision in bundle.get("decisions") or []:
            named = by_digest.get(gate_body(decision)["review"])
            if named is None:
                raise RecordError("review-gate.wrong-review", "a decision names no version")
            _review.check_gate(decision, named)
            if _review.digest(decision) not in digests:
                digests.add(_review.digest(decision))
                decisions.append(decision)
        known = _review_store.versions(root, tenant, review_id)
        if known:
            if known == versions and _review_store.decisions(root, tenant, review_id) == decisions:
                continue
            raise Conflict(f"review {review_id} already exists here with other content")
        plan.reviews.append((review_id, versions, decisions))


def _project_versions(root, tenant: str, manifests: Any, plan: Plan) -> None:
    if not manifests:
        return
    _chain(manifests, _project.check, "project")
    if any(_project.check(m)["tenant"] != tenant for m in manifests):
        raise RecordError("project.malformed", "the manifest names another tenant")
    known = _project_store.count(root, tenant)
    if known:
        stored = [_project_store.read(root, tenant, seq) for seq in range(known)]
        if stored == manifests:
            return
        raise Conflict("this tenant already has another project manifest")
    plan.project = list(manifests)


def make_plan(service: Any, identity: Any, tenant: str, root, request: dict) -> Plan:
    plan = Plan()
    _refs(service, identity, tenant, request.get("refs") or {}, plan)
    _reviews(root, tenant, request.get("reviews") or [], plan)
    _project_versions(root, tenant, request.get("project") or [], plan)
    return plan


def _apply(service: Any, root, tenant: str, plan: Plan) -> bool:
    try:
        return apply.commit(service.index, root, tenant, apply.stage(root, tenant, plan))
    except BaseException:
        apply.recover(service.index, root, tenant)  # unchanged, or fully imported
        raise


def route(app: Any, identity: Any, tenant: str, environ: dict, sr) -> Any:
    service = app.service
    root = getattr(service.objects, "root", None)
    if root is None or not supported(service.index):
        return app._json_response(sr, "404 Not Found", {"error": "not found"})
    try:
        service._authorize(identity, "update_ref", tenant)
    except PermissionError:
        try:
            reads.readable(service, identity, tenant, "read_ref")
        except reads.Hidden:  # a caller who may not even read the tenant: the uniform 404
            return app._json_response(sr, "404 Not Found", {"error": "not found"})
        raise
    request = app._json(environ, "refs", "reviews", "project")
    with _LOCK:
        apply.recover(service.index, root, tenant)
        try:
            plan = make_plan(service, identity, tenant, root, request)
        except Conflict as exc:
            service._audit(identity, tenant, "update_ref", "conflict", {"name": "import"})
            return app._json_response(sr, "409 Conflict", {"imported": False, "conflict": str(exc)})
        except RecordError as exc:
            service._audit(identity, tenant, "update_ref", "refused", {"import": exc.code})
            return app._json_response(sr, "400 Bad Request", {"error": str(exc), "code": exc.code})
        changed = plan.rows or plan.reviews or plan.project
        if changed and not _apply(service, root, tenant, plan):
            service._audit(identity, tenant, "update_ref", "conflict", {"name": "import"})
            body = {"imported": False, "conflict": "the tenant changed"}
            return app._json_response(sr, "409 Conflict", body)
    _announce(service, identity, tenant, plan)
    body = {"imported": True, "refs": len(plan.rows), "reviews": len(plan.reviews),
            "project_versions": len(plan.project)}  # fmt: skip
    return app._json_response(sr, "200 OK", body)


def _announce(service: Any, identity: Any, tenant: str, plan: Plan) -> None:
    """Audit (and so log) what the import added, as the single-item routes would."""
    if plan.rows:
        names = [name for name, _ in plan.rows]
        head = {"name": plan.rows[0][0], "new": plan.rows[0][1]}
        service._audit(identity, tenant, "update_ref", "ok",
                       {"names": names, "txn": True, "import": True, **head})  # fmt: skip
    for review_id, versions, _ in plan.reviews:
        details = {"name": f"reviews/{review_id}", "new": _review.digest(versions[-1])}
        service._audit(identity, tenant, "update_ref", "ok", details)
    if plan.project:
        details = {"name": "project/manifest", "new": _project.digest(plan.project[-1])}
        service._audit(identity, tenant, "update_ref", "ok", details)
    hub = getattr(service, "events", None)
    for name, new in plan.rows if hub else ():
        hub.ref_moved(tenant, name, None, new, False)


__all__ = ["MAX_REFS", "MAX_REVIEWS", "capabilities", "make_plan", "route"]
