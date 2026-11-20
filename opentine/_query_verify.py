"""``tine query --verify``: re-check the objects behind returned rows (0.65).

The index is derived and can be edited by anyone who can write the file, so
``--verify`` goes back to the source of each row that names an ``oid`` and
marks it:

``verified``    the object (or record) is intact, re-derives the values the row
                shows, carries a valid Ed25519 signature, and its signer holds
                a role in the owner-pinned key roles (:mod:`opentine._key_roles_pin`)
``unverified``  intact and consistent, but unsigned (runs and steps are
                content-addressed, not signed) or signed by a key without a
                pinned role
``failed``      missing, altered, its signature does not verify, or the index
                row disagrees with what the object derives

Only columns named like an index column are compared, so an aggregate or a
renamed column is not checked. ``unverified`` is advisory (D12); ``failed``
makes the command exit 1.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine import _query_containment as qc
from opentine import _query_experiments as qx
from opentine import _query_merges as qm
from opentine import _query_research as qe
from opentine import _query_rows as qr
from opentine._query_build import eval_files, eval_source, remembered_dirs

#: The pinned role a signer needs for a row of these tables to be ``verified``;
#: a signer that also holds ``optimizer`` never verifies them (key separation).
#: A reproduce report signed by an ``optimizer`` key never verifies either.
ROLE_FOR = {"evals": "scorer", "monitor_verdicts": "monitor",
            "oversight_decisions": "approver"}  # fmt: skip
_HEX = set("0123456789abcdef")


def _roles(store: Path) -> dict[str, list[str]]:
    from opentine._key_roles_pin import pinned

    by_key: dict[str, list[str]] = {}
    for role, keys in sorted((pinned(store) or {}).items()):
        for key in keys or []:
            by_key.setdefault(key, []).append(role)
    return by_key


def _derive(repo: Any, oid: str, table: str | None, db: Any,
            row: dict[str, Any]) -> tuple[dict | None, str | None]:  # fmt: skip
    """The row the source derives for *oid* now, or ``(None, why it failed)``."""
    store = Path(repo.path)
    if oid.startswith("event:"):
        payload = repo.get(oid).payload()
        return (qr.step_row(oid, payload) if isinstance(payload, dict) else None), None
    if oid.split(":", 1)[0] in ("run", "attestation", "annotation"):
        found = qr.object_rows(repo, oid)
        rows = [r for name, rs in found.items() if name != "steps" for r in rs]
        return (rows[0] if rows else None), None if rows else "the object is not indexable"
    if table == "evals":
        source, line = db.execute("SELECT source, line FROM evals WHERE oid = ?", (oid,)).fetchone()
        if source not in eval_files(store, remembered_dirs(store)):
            return None, "the source is not an indexed eval file"
        raw = eval_source(store, source).read_bytes().split(b"\n")[line - 1].rstrip(b"\r")
        if "sha256:" + hashlib.sha256(raw).hexdigest() != oid:
            return None, "the verdict line changed"
        return qr.eval_row(oid, source, line, json.loads(raw)), None
    if table in qe.FILE_TABLES:
        return qe.derive(store, table, oid, db, row)
    if table in qx.TABLES:
        return qx.derive(store, remembered_dirs(store, "experiments"), table, oid, db, row)
    if table == "lineage_variants":
        (variant,) = db.execute("SELECT variant FROM lineage_variants WHERE oid = ?",
                                (oid,)).fetchone()  # fmt: skip
        if not (len(variant) == 71 and variant.startswith("sha256:") and set(variant[7:]) <= _HEX):
            raise ValueError("not a variant id")
        raw = (store / "lineage" / "variants" / f"{variant[7:]}.json").read_bytes()
        if "sha256:" + hashlib.sha256(raw).hexdigest() != oid:
            return None, "the lineage record changed"
        rows = qr.lineage_rows({f"variants/{variant[7:]}.json": raw})["lineage_variants"]
        return (rows[0] if rows else None), None
    return None, "no source holds this oid"


def _step_place(repo: Any, oid: str, row: dict[str, Any]) -> str | None:
    """Why the row's ``run``/``seq`` do not hold this step, or ``None`` when they do."""
    run, seq = row.get("run"), row.get("seq")
    if run is None and seq is None:
        return None
    try:
        events = repo.get(run).payload().get("events") or []
        held = oid in events if seq is None else events[seq] == oid
    except Exception:  # noqa: BLE001 - an unreadable run cannot hold the step
        held = False
    return None if held else "the step is not at that place in that run"


def _table_of(db: Any, oid: str, row: dict[str, Any]) -> str | None:
    """The table holding *oid*; a manifest's result rows share its oid and add an ``id``."""
    results = ("experiment_results",) if "id" in row else ()
    items = ("elicit_items",) if "id" in row else ()
    for table in ("evals", "lineage_variants", "monitor_verdicts", "oversight_decisions",
                  *results, "experiments", "reproductions", "sabotage_tasks", *items,
                  "elicit_links", "history_merges", *qc.TABLES):  # fmt: skip
        if db.execute(f"SELECT 1 FROM {table} WHERE oid = ? LIMIT 1", (oid,)).fetchone():
            return table
    return None


def check(repo: Any, oid: str, row: dict[str, Any], db: Any,
          roles: dict[str, list[str]]) -> dict[str, Any]:  # fmt: skip
    """``{"oid", "status", "reason", "signer", "roles"}`` for one returned row."""
    out: dict[str, Any] = {"oid": oid, "signer": None, "roles": []}
    try:
        table = _table_of(db, oid, row)
        derived, why = _derive(repo, oid, table, db, row)
        if derived is not None and oid.startswith("event:"):
            why = _step_place(repo, oid, row)
            derived = None if why else derived
    except Exception as exc:  # noqa: BLE001 - any read failure fails the row
        derived, why = None, f"the source cannot be read ({type(exc).__name__})"
    if derived is None:
        return {**out, "status": "failed", "reason": why or "the source derives no row"}
    for column, value in row.items():
        context = qr.CONTEXT - {"run"} if table == "evals" else qr.CONTEXT
        if column in derived and column not in context and derived[column] != value:
            return {**out, "status": "failed",
                    "reason": f"the index row disagrees with the source on {column}"}  # fmt: skip
    signer = derived.get("signer")
    out["signer"], out["roles"] = signer, roles.get(signer, []) if signer else []
    if "signed" not in derived:
        return {**out, "status": "unverified", "reason": "content-addressed, not signed"}
    if not derived["signed"]:
        return {**out, "status": "failed" if signer else "unverified",
                "reason": "the signature does not verify" if signer else "not signed"}  # fmt: skip
    if not out["roles"]:
        return {**out, "status": "unverified", "reason": "the signer holds no pinned role"}
    if table == "reproductions" and "optimizer" in out["roles"]:
        return {**out, "status": "unverified", "reason": "the report signer holds optimizer"}
    need = ROLE_FOR.get(table or "")
    if need and (need not in out["roles"] or "optimizer" in out["roles"]):
        return {**out, "status": "unverified", "reason": f"the signer holds no {need} role"}
    roles = {**qe.ROLES_FOR, **qm.ROLES_FOR, **qc.ROLES_FOR}.get(
        "elicit_links" if table == "elicit_items" else table or ""
    )
    if roles and (not set(roles) & set(out["roles"]) or "optimizer" in out["roles"]):
        return {**out, "status": "unverified",
                "reason": f"the signer holds no {' or '.join(roles)} role"}  # fmt: skip
    return {**out, "status": "verified", "reason": "signature valid, signer pinned"}


def verify_rows(repo: Any, rows: list[dict[str, Any]], db: Any) -> list[dict[str, Any]]:
    """One check per returned row; a row without an ``oid`` column is ``unverified``."""
    roles = _roles(Path(repo.path))
    out = []
    for row in rows:
        oid = row.get("oid")
        if not isinstance(oid, str):
            out.append({"oid": None, "status": "unverified", "reason": "the row has no oid",
                        "signer": None, "roles": []})  # fmt: skip
            continue
        out.append(check(repo, oid, row, db, roles))
    return out


__all__ = ["ROLE_FOR", "check", "verify_rows"]
