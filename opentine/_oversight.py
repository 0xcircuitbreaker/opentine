"""Oversight decisions (0.64): signed annotations chained by ``previous_id``.

An item in the oversight queue is named by a string:

* ``promotion:LABEL:run:sha256:HEX`` -- a candidate for a label (lineage
  promotions and threshold-crossing evals route here);
* ``monitor:attestation:sha256:HEX`` -- a held monitor verdict (0.62);
* ``integrity:attestation:sha256:HEX`` -- a held integrity taint (a ``fail:``).

Each item has an anchor: a blob holding ``{"convention":
"opentine.oversight-item/1", "item": ITEM}`` (so its id follows from the name
alone). Every decision is an existing ``annotation`` object on that anchor::

    {"target_id": ANCHOR, "previous_id": PRIOR_DECISION_OR_NULL,
     "value": {"convention": "opentine.oversight-decision/1", "item",
               "decision": "request|approve|reject", "bind", "human", "note",
               "decided_at", ["viewed": {"evidence": [OID...], "at": ISO}]},
     "signer": "sha256:<fingerprint>", "signature": {tine-attest block, Ed25519}}

``bind`` ties a promotion decision to the label's holder and history length
(``{"label", "candidate", "previous", "sequence"}``), so a move since makes it
stale. Every decision is held (``oversight-decision:ITEM``) and ``tine hold
release`` refuses it, so a loop cannot delete an approval or rejection it
would want gone; the held ids are the fast path to each item's newest
decision, and :func:`by_objects` rebuilds the same chains from the annotation
objects alone. No object kind is added.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from opentine.kernel import canonical_json

ITEM = "opentine.oversight-item/1"
DECISION = "opentine.oversight-decision/1"
DECISIONS = ("request", "approve", "reject")


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def promotion_item(label: str, candidate: str) -> str:
    return f"promotion:{label}:{candidate}"


def parse_item(item: str) -> dict[str, Any]:
    """``{"source", "label", "candidate", "oid"}`` for an item name."""
    from opentine._promote_checks import LABEL_RE, RUN_RE
    from opentine._transcript_flags import LABEL_RE as FLAG_LABEL_RE

    source, _, rest = item.partition(":")
    if source == "promotion":
        label, _, candidate = rest.partition(":")
        if LABEL_RE.fullmatch(label) and RUN_RE.fullmatch(candidate):
            return {"source": source, "label": label, "candidate": candidate, "oid": None}
    elif source in ("monitor", "integrity", "containment", "organism") and rest.startswith(
        "attestation:sha256:"
    ):
        return {"source": source, "label": None, "candidate": None, "oid": rest}
    elif source == "budget" and rest.startswith("annotation:sha256:"):  # 0.69: a budget flag
        return {"source": source, "label": None, "candidate": None, "oid": rest}
    elif source == "custody" and rest.startswith(("attestation:sha256:", "blob:sha256:")):
        # 0.72: a custody gap (an event attestation) or a refused tagged load (an access blob)
        return {"source": source, "label": None, "candidate": None, "oid": rest}
    elif source == "transcript":  # 0.74: a behaviour flag, or a run like a flagged one
        if rest.startswith("attestation:sha256:"):
            return {"source": source, "label": None, "candidate": None, "oid": rest}
        label, _, run = rest.partition(":")
        if FLAG_LABEL_RE.fullmatch(label) and RUN_RE.fullmatch(run):
            return {"source": source, "label": label, "candidate": None, "oid": run}
    raise ValueError(f"{item!r} is not an oversight item (promotion:LABEL:RUN, monitor:"
                     "ATTESTATION, integrity:|containment:|organism:ATTESTATION, "
                     "budget:ANNOTATION, custody:ATTESTATION|BLOB, transcript:ATTESTATION "
                     "or transcript:LABEL:RUN)")  # fmt: skip


def anchor_bytes(item: str) -> bytes:
    return canonical_json({"convention": ITEM, "item": item})


def anchor(repo: Any, item: str) -> str:
    """The anchor blob's id, stored if it is not yet."""
    return repo.put("blob", anchor_bytes(item), redact=False)


def decide(repo: Any, item: str, decision: str, key: Any, *, bind: dict | None = None,
           human: str | None = None, note: str = "", at: str | None = None,
           viewed: dict[str, Any] | None = None) -> str:  # fmt: skip
    """Sign, store and hold one decision; the annotation id."""
    from opentine._signing_pins import key_fingerprint
    from opentine.attest_signing import sign_attestation

    parse_item(item)
    if decision not in DECISIONS:
        raise ValueError(f"decision is one of {', '.join(DECISIONS)}")
    target = anchor(repo, item)
    previous = head(repo, item)
    value = {"convention": DECISION, "item": item, "decision": decision, "bind": bind,
             "human": human, "note": note, "decided_at": at or now()}  # fmt: skip
    if viewed is not None:  # what the approver looked at, and when (fatigue metrics)
        value["viewed"] = viewed
    payload = {"target_id": target, "previous_id": previous, "value": value,
               "signer": key_fingerprint(key.public_key().public_bytes_raw())}  # fmt: skip
    payload["signature"] = sign_attestation(payload, key, algorithm="ed25519",
                                            signed_at=value["decided_at"])  # fmt: skip
    oid = repo.put("annotation", payload, redact=False)
    hold(repo, oid, item)
    return oid


def hold(repo: Any, oid: str, item: str) -> None:
    from opentine.repository._holds import OVERSIGHT_DECISION, edit_holds, holds_path
    from opentine.repository._link_touch import touch_links

    touch_links(repo, [oid])
    row = {"oid": oid, "target": OVERSIGHT_DECISION + item}
    edit_holds(holds_path(repo), lambda rows: [*(r for r in rows if r != row), row])


def read(repo: Any, oid: str) -> dict[str, Any] | None:
    """A decision row ``{"id", "item", "anchor", "previous", "signer", "signed", ...}``."""
    from opentine.attest_signing import verify_attestation

    try:
        payload = repo.get(oid).payload()
    except Exception:  # noqa: BLE001 - an unreadable object is no decision
        return None
    value = payload.get("value") if isinstance(payload, dict) else None
    if not isinstance(value, dict) or value.get("convention") != DECISION:
        return None
    result = verify_attestation(payload, trust_embedded=True)
    signed = bool(result.ok and result.algorithm == "ed25519")
    if signed:
        from opentine._signing_pins import key_fingerprint

        public = payload["signature"].get("public_key", "")
        signed = key_fingerprint(bytes.fromhex(public)) == payload.get("signer")
    return {"id": oid, "item": value.get("item"), "anchor": payload.get("target_id"),
            "previous": payload.get("previous_id"), "signer": payload.get("signer"),
            "signed": signed, "decision": value.get("decision"), "bind": value.get("bind"),
            "human": value.get("human"), "note": value.get("note", ""),
            "decided_at": value.get("decided_at"), "viewed": value.get("viewed")}  # fmt: skip


def chain(repo: Any, head: str | None) -> list[dict[str, Any]]:
    """Decisions from the first to *head*, following ``previous_id``."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    while head and head not in seen:
        seen.add(head)
        row = read(repo, head)
        if row is None:
            break
        out.append(row)
        head = row["previous"]
    return out[::-1]


def _held_ids(repo: Any) -> list[str]:
    from opentine.repository._holds import OVERSIGHT_DECISION, holds_path, read_holds

    rows = read_holds(holds_path(repo))
    return sorted({r["oid"] for r in rows if r["target"].startswith(OVERSIGHT_DECISION)})


def _group(repo: Any, rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    rows = [r for r in rows if r["anchor"] == anchor_oid_of(r["item"])]
    out: dict[str, list[dict[str, Any]]] = {}
    for item in sorted({r["item"] for r in rows}):
        mine = {r["id"]: r for r in rows if r["item"] == item}
        # Every decision counts, ordered by time: a fork of the previous_id chain
        # (concurrent, or forged to start after a rejection) hides nothing.
        out[item] = sorted(mine.values(), key=lambda r: (str(r["decided_at"] or ""), r["id"]))
    return out


def by_holds(repo: Any) -> dict[str, list[dict[str, Any]]]:
    """``{item: decisions}`` read from the held decision ids (the fast path)."""
    return _group(repo, [r for oid in _held_ids(repo) if (r := read(repo, oid)) is not None])


def by_objects(repo: Any) -> dict[str, list[dict[str, Any]]]:
    """``{item: decisions}`` rebuilt from the annotation objects alone."""
    return _group(repo, [r for oid in repo.iter_oids() if oid.startswith("annotation:")
                         if (r := read(repo, oid)) is not None])  # fmt: skip


def head(repo: Any, item: str) -> str | None:
    rows = by_holds(repo).get(item)
    return rows[-1]["id"] if rows else None


def anchor_oid_of(item: Any) -> str | None:
    from opentine.kernel import ObjectEnvelope

    try:
        parse_item(item)
    except (TypeError, ValueError):
        return None
    return ObjectEnvelope.create("blob", anchor_bytes(item), 1).oid


__all__ = ["DECISION", "DECISIONS", "ITEM", "anchor", "anchor_oid_of", "by_objects", "by_holds",
           "chain", "decide", "head", "now", "parse_item", "promotion_item", "read"]  # fmt: skip
