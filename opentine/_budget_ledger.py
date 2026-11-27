"""The budget ledger (0.69): signed, held, append-only spend for one subject.

Each entry is an existing ``annotation`` object whose ``value`` follows the
claim convention ``opentine.budget-ledger/1``::

    {"convention": "opentine.budget-ledger/1", "subject": "loop:opt",
     "entry": "spend" | "policy" | "flag", "at": RFC3339, "at_ms": INT, ...}

* ``spend``: ``run`` and ``cost`` (the run's ``tine cost`` aggregate,
  :func:`opentine._cost_export.aggregate`, copied as recorded), plus
  ``gpu_hours`` and ``egress_bytes``;
* ``policy``: ``policy``, a signed ``opentine-budget-policy/1`` document;
* ``flag``: ``code``, ``detail`` and ``about`` (the entry it flags): an
  integrity violation or a reached limit routed to the oversight queue;
* ``deny`` (0.87): ``code``, ``detail`` and ``about`` (the policy entry in
  force), plus ``model``, ``path``, ``role``, ``run`` and ``call``: a model call
  the ``tine record`` proxy refused (:mod:`opentine._record_budget`).

A ``spend`` entry written by the proxy also carries ``call``, ``phase``
(``reserve`` or ``settle``), ``role``, ``model`` and ``source``
(:mod:`opentine._budget_spend`). Appends are serialised by
:mod:`opentine._budget_lock`.

``target_id`` is an anchor blob naming the subject and ``previous_id`` the
entry before it, so ids chain like oversight decisions. Every entry is held
(``budget-ledger:SUBJECT``, released never) and a flag also under
``budget-flag:SUBJECT``, which the oversight queue reads. Entries are read from
the holds, not from a head ref, so deleting a ref hides nothing.
"""

from __future__ import annotations

from typing import Any

from opentine._utc import rfc3339_utc
from opentine.kernel import canonical_json

CONVENTION = "opentine.budget-ledger/1"
ENTRIES = ("spend", "policy", "flag", "deny")


def rfc3339(ms: int) -> str:
    return rfc3339_utc(ms / 1000)


def anchor(repo: Any, subject: str) -> str:
    return repo.put("blob", canonical_json({"convention": CONVENTION, "subject": subject}),
                    redact=False)  # fmt: skip


def _hold(repo: Any, oid: str, target: str) -> None:
    from opentine.repository._holds import hold_row

    hold_row(repo, oid, target)


def held_ids(repo: Any, prefix: str, subject: str | None = None) -> list[str]:
    from opentine.repository._holds import holds_path, read_holds

    rows = read_holds(holds_path(repo))
    return sorted({r["oid"] for r in rows if r["target"].startswith(prefix)
                   and (subject is None or r["target"] == prefix + subject)})  # fmt: skip


def append(repo: Any, subject: str, entry: str, fields: dict[str, Any], key: Any, *,
           at_ms: int) -> str:  # fmt: skip
    """Sign, store and hold one entry after the current head; its annotation id."""
    from opentine._budget_lock import locked
    from opentine._budget_policy import subject as check_subject

    check_subject(subject)
    if entry not in ENTRIES:
        raise ValueError(f"a ledger entry is one of {', '.join(ENTRIES)}")
    with locked(repo):
        return _append(repo, subject, entry, fields, key, at_ms)


def _append(repo: Any, subject: str, entry: str, fields: dict[str, Any], key: Any,
            at_ms: int) -> str:  # fmt: skip
    from opentine._signing_pins import key_fingerprint
    from opentine.attest_signing import sign_attestation
    from opentine.repository._holds import BUDGET_FLAG, BUDGET_LEDGER

    rows = entries(repo, subject)
    value = {"convention": CONVENTION, "subject": subject, "entry": entry,
             "at": rfc3339(at_ms), "at_ms": int(at_ms), **fields}  # fmt: skip
    payload = {"target_id": anchor(repo, subject), "value": value,
               "previous_id": rows[-1]["id"] if rows else None,
               "signer": key_fingerprint(key.public_key().public_bytes_raw())}  # fmt: skip
    payload["signature"] = sign_attestation(payload, key, algorithm="ed25519",
                                            signed_at=value["at"])  # fmt: skip
    oid = repo.put("annotation", payload, redact=False)
    _hold(repo, oid, BUDGET_LEDGER + subject)
    if entry == "flag":
        _hold(repo, oid, BUDGET_FLAG + subject)
    return oid


def read(repo: Any, oid: str) -> dict[str, Any] | None:
    """``{"id", "previous", "signer", "signed", "value"}``, or ``None`` for no entry."""
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    try:
        payload = repo.get(oid).payload()
    except Exception:  # noqa: BLE001 - an unreadable object is no entry
        return None
    value = payload.get("value") if isinstance(payload, dict) else None
    if not isinstance(value, dict) or value.get("convention") != CONVENTION:
        return None
    result = verify_attestation(payload, trust_embedded=True)
    signer = payload.get("signer")
    signed = bool(result.ok and result.algorithm == "ed25519"
                  and used_key_fingerprint(payload.get("signature")) == signer)  # fmt: skip
    return {"id": oid, "previous": payload.get("previous_id"), "signer": signer,
            "signed": signed, "value": value}  # fmt: skip


def entries(repo: Any, subject: str) -> list[dict[str, Any]]:
    """Every held entry of *subject*, in chain order (forks and orphans keep their place).

    Order is by chain depth, then ``at_ms``, then id: a fork cannot hide spend,
    and :func:`forks` reports it.
    """
    from opentine.repository._holds import BUDGET_LEDGER

    rows = [r for oid in held_ids(repo, BUDGET_LEDGER, subject) if (r := read(repo, oid))]
    rows = [r for r in rows if r["value"].get("subject") == subject]
    by_id = {r["id"]: r for r in rows}
    depth: dict[str, int] = {}

    for row in rows:  # iterative: a long ledger never hits the recursion limit
        chain, cur, seen = [], row, set()
        while cur is not None and cur["id"] not in depth and cur["id"] not in seen:
            seen.add(cur["id"])
            chain.append(cur)
            cur = by_id.get(cur["previous"])
        base = depth.get(cur["id"], -1) if cur is not None else -1
        for item in reversed(chain):
            base += 1
            depth[item["id"]] = base
    key = lambda r: (depth[r["id"]], int(r["value"].get("at_ms") or 0), r["id"])  # noqa: E731
    return sorted(rows, key=key)


def forks(rows: list[dict[str, Any]]) -> list[str]:
    """Ids of entries whose ``previous`` another entry already continues, or that is not held."""
    ids = {r["id"] for r in rows}
    seen: set[Any] = set()
    out = []
    for row in rows:
        parent = row["previous"]
        if parent in seen or (parent is not None and parent not in ids):
            out.append(row["id"])
        seen.add(parent)
    return out


__all__ = ["CONVENTION", "ENTRIES", "anchor", "append", "entries", "forks", "held_ids", "read",
           "rfc3339"]  # fmt: skip
