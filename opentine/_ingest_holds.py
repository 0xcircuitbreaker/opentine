"""Where an ingest stream's records survive a deleted ref or file (0.77).

Every sampling policy is held as ``ingest-policy:STREAM`` and the newest batch
as ``ingest-head:STREAM`` (one row per stream, moved forward by each append).
Batches chain to their predecessor through ``evidence_ids``, so the held head
keeps the whole chain reachable. ``tine hold release`` refuses both prefixes.
"""

from __future__ import annotations

from typing import Any

from opentine.repository._holds import INGEST_HEAD, INGEST_POLICY


def _edit(repo: Any, change) -> None:  # noqa: ANN001
    from opentine.repository._holds import edit_holds, holds_path

    edit_holds(holds_path(repo), change)


def hold_policy(repo: Any, stream: str, oid: str) -> None:
    from opentine.repository._link_touch import touch_links

    touch_links(repo, [oid])
    row = {"oid": oid, "target": INGEST_POLICY + stream}
    _edit(repo, lambda rows: [*(r for r in rows if r != row), row])


def move_head(repo: Any, stream: str, expected: str | None, oid: str, *,
              prefix: str = INGEST_HEAD) -> None:  # fmt: skip
    """Move the held head (*prefix*: batches, or 0.84 segments) of *stream* (compare and swap)."""
    from opentine._ingest_policy import IngestError
    from opentine.repository._link_touch import touch_links

    touch_links(repo, [oid])
    target = prefix + stream

    def change(rows: list[dict[str, str]]) -> list[dict[str, str]]:
        current = [r["oid"] for r in rows if r["target"] == target]
        if current != ([expected] if expected else []):
            raise IngestError(f"stream {stream} moved while this batch was written; retry")
        return [*(r for r in rows if r["target"] != target), {"oid": oid, "target": target}]

    _edit(repo, change)


def _rows(repo: Any, target: str) -> list[str]:
    from opentine.repository._holds import holds_path, read_holds

    return sorted({r["oid"] for r in read_holds(holds_path(repo)) if r["target"] == target})


def head(repo: Any, stream: str, *, prefix: str = INGEST_HEAD) -> str | None:
    """The held newest batch (or 0.84 segment) of *stream*; two rows fail closed."""
    from opentine._ingest_policy import IngestError

    rows = _rows(repo, prefix + stream)
    if len(rows) > 1:
        raise IngestError(f"stream {stream} has {len(rows)} held heads")
    return rows[0] if rows else None


def hold(repo: Any, target: str, oid: str) -> None:
    """Hold *oid* under *target* (0.84: a segment's audits), never released."""
    from opentine.repository._link_touch import touch_links

    touch_links(repo, [oid])
    row = {"oid": oid, "target": target}
    _edit(repo, lambda rows: [*(r for r in rows if r != row), row])


def held(repo: Any, target: str) -> list[str]:
    return _rows(repo, target)


def policies(repo: Any, stream: str) -> list[str]:
    return _rows(repo, INGEST_POLICY + stream)


def streams(repo: Any) -> list[str]:
    from opentine.repository._holds import holds_path, read_holds

    names = {r["target"].split(":", 1)[1] for r in read_holds(holds_path(repo))
             if r["target"].startswith((INGEST_HEAD, INGEST_POLICY))}  # fmt: skip
    return sorted(names)


def write(repo: Any, target: str, value: dict[str, Any], key: Any, *, previous: str | None,
          signed_at: str, verbatim: tuple[str, ...] = ()) -> str:  # fmt: skip
    """Sign and store one record: an ``annotation`` whose ``value`` is the claim.

    The payload is redacted before it is signed (as ``attest`` does), so the
    signature covers the bytes readers read. *verbatim* names claim fields that
    are verified public data a reader recomputes byte for byte (an audit's signed
    op log checkpoint): redaction is not allowed to rewrite them, since a random
    base64 root ending ``pw=`` reads as a credential assignment to the scrubber.
    """
    from opentine._signing_pins import key_fingerprint
    from opentine._v3_guards import guarded_redaction
    from opentine.attest_signing import sign_attestation

    events = value.get("events") if isinstance(value.get("events"), str) else None
    small = {k: v for k, v in value.items() if events is None or k != "events"}
    payload = {"target_id": target, "value": small, "previous_id": previous,
               "signer": key_fingerprint(key.public_key().public_bytes_raw())}  # fmt: skip
    payload = guarded_redaction(payload, where="v3 'annotation'")
    for field in verbatim:
        if field in small:
            payload["value"][field] = small[field]
    if events is not None:  # a batch's JSON Lines, already redacted as a blob is
        payload["value"]["events"] = events
    payload["signature"] = sign_attestation(payload, key, algorithm="ed25519",
                                            signed_at=signed_at)  # fmt: skip
    return repo.put("annotation", payload, redact=False)


def read(repo: Any, oid: str, convention: str) -> dict[str, Any] | None:
    """``{"id", "claim", "signer", "signed", "target", "previous"}`` of a signed record.

    ``signed`` holds only for a verifying Ed25519 signature whose signing key is
    the recorded ``signer``. ``None`` for an unreadable object or another claim.
    """
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    try:
        envelope = repo.get(oid)
        payload = envelope.payload()
    except Exception:  # noqa: BLE001 - an unreadable object is no record
        return None
    if envelope.object_type != "annotation" or not isinstance(payload, dict):
        return None
    claim = payload.get("value")
    if not isinstance(claim, dict) or claim.get("convention") != convention:
        return None
    result = verify_attestation(payload, trust_embedded=True)
    signer = payload.get("signer")
    signed = bool(result.ok and result.algorithm == "ed25519"
                  and used_key_fingerprint(payload.get("signature")) == signer)  # fmt: skip
    return {"id": oid, "claim": claim, "signer": signer if signed else None, "signed": signed,
            "target": payload.get("target_id"),
            "previous": payload.get("previous_id")}  # fmt: skip


__all__ = [
    "head",
    "hold",
    "hold_policy",
    "held",
    "move_head",
    "policies",
    "read",
    "streams",
    "write",
]
