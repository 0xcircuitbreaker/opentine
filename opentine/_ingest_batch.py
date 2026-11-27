"""Signed ingest batches (0.77): ``opentine.ingest-batch/1``.

``tine ingest --batch FILE`` (and ``POST /v1/ingest`` of ``tine ingest serve``)
takes a batch of events or episodes as JSON Lines, one object per line; an
event's kind is its ``kind`` (else ``type``) string, or ``event``. The stream's
sampling policy (:mod:`opentine._ingest_policy`) decides per event, by its
stream index, what is captured. The batch is one signed ``annotation`` on the
stream's anchor blob (no new kind) whose ``value`` follows the convention::

    {"convention": "opentine.ingest-batch/1", "stream": S, "seq": N,
     "previous": BATCH-ID | null, "policy": POLICY-ID, "policy_digest": "sha256:...",
     "first_index": I, "next_index": I + received, "received": R, "captured": C,
     "dropped": D, "dropped_by": {"kind": n, "rate": n}, "input_sha256": "sha256:...",
     "events": "<JSON Lines>", "at": RFC3339}

``events`` holds one line ``{"e": EVENT, "i": INDEX, "k": KIND}`` per captured
event (sorted keys, no spaces), redacted like any stored blob
(:func:`opentine.redaction.redact_blob`) before the batch is signed unless the
policy says ``"redact": false``.

``previous_id`` (and ``previous``) names the previous batch, so batch ids form
a hash chain: a dropped, reordered or replayed batch breaks ``seq``,
``previous`` or the index range, and ``tine ingest verify`` reports it. The
held head keeps every batch reachable through that chain.

Durability: a batch is written inside one write batch
(:mod:`opentine.repository._write_batch`), one durability point per batch; the
held head moves only after the batch is durable.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from opentine import _ingest_holds, _ingest_policy, _key_roles_pin
from opentine._ingest_policy import IngestError
from opentine._json_shallow import unique_pairs
from opentine._utc import rfc3339_utc
from opentine.redaction import redact_blob

CONVENTION = "opentine.ingest-batch/1"
MAX_EVENTS = 1_000_000
MAX_LINE_BYTES = 1 << 20
_LINE = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False)  # fmt: skip


def _finite(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(f"{text} is not a finite number")
    return value


def _constant(text: str) -> Any:
    raise ValueError(f"{text} is not JSON")


def parse(data: bytes) -> list[tuple[str, Any]]:
    """``[(kind, event)]`` from JSON Lines bytes (untrusted: nesting-bounded)."""
    from opentine import _json_shallow

    out: list[tuple[str, Any]] = []
    for number, line in enumerate(data.split(b"\n"), 1):
        line = line.strip()
        if not line:
            continue
        if len(line) > MAX_LINE_BYTES:
            raise IngestError(f"line {number} is longer than {MAX_LINE_BYTES} bytes")
        if len(out) >= MAX_EVENTS:
            raise IngestError(f"a batch holds at most {MAX_EVENTS} events")
        try:
            event = _json_shallow.loads(
                line.decode("utf-8"),
                object_pairs_hook=unique_pairs,
                parse_float=_finite,
                parse_constant=_constant,
            )
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise IngestError(f"line {number} is not a JSON object: {exc}") from exc
        if not isinstance(event, dict):
            raise IngestError(f"line {number} is not a JSON object")
        kind = event.get("kind", event.get("type", "event"))
        if not isinstance(kind, str) or not _ingest_policy.KIND.fullmatch(kind):
            raise IngestError(f"line {number} has an invalid kind {kind!r}")
        out.append((kind, event))
    return out


def _refusal(row: dict[str, Any], roles: dict[str, Any]) -> str | None:
    """Why a policy row may not take effect at write time (the check verify applies)."""
    return _ingest_policy.judge(row["signer"], roles)


def current_policy(repo: Any, stream: str) -> dict[str, Any]:
    """The stream's newest policy signed by a pinned policy key (``issued_at``, then id).

    Only role-approved policies are candidates, so an unroled key's self-claimed
    future ``issued_at`` never wins; none approved refuses (fails closed).
    """
    rows = [r for oid in _ingest_holds.policies(repo, stream)
            if (r := _ingest_holds.read(repo, oid, _ingest_policy.CONVENTION))]  # fmt: skip
    rows = [r for r in rows if r["signed"] and r["claim"].get("stream") == stream]
    if not rows:
        raise IngestError(f"stream {stream} has no signed sampling policy: "
                          "run tine ingest policy first")  # fmt: skip
    roles = _key_roles_pin.resolve(repo.path)
    rows = [r for r in rows if _refusal(r, roles) is None]
    if not rows:  # fail closed, as tine ingest verify does
        raise IngestError(f"stream {stream} has no sampling policy signed by a pinned policy key")
    return max(rows, key=lambda r: (str(r["claim"].get("issued_at")), r["id"]))


def _refuse_optimizer(repo: Any, key: Any) -> None:
    from opentine._key_roles_pin import resolve
    from opentine._signing_pins import key_fingerprint

    roles = resolve(repo.path)
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    if roles.get("status") == "pinned" and signer in (roles.get("roles") or {}).get(
        "optimizer", []
    ):
        raise IngestError("an optimizer key may not sign ingest batches")


def append(repo: Any, stream: str, data: bytes, key: Any, *, at_ms: int,
           policy_id: str | None = None) -> dict[str, Any]:  # fmt: skip
    """Sample, store, sign and chain one batch; its summary (``id`` and the claim)."""
    from opentine.repository import _write_batch

    _ingest_policy.stream_name(stream)
    events = parse(data)
    if policy_id is None:
        policy_row = current_policy(repo, stream)
    else:
        policy_row = _ingest_holds.read(repo, policy_id, _ingest_policy.CONVENTION)
        if policy_row is None or not policy_row["signed"]:
            raise IngestError(f"{policy_id} is not a signed ingest policy")
        if policy_id not in _ingest_holds.policies(repo, stream):
            raise IngestError(f"{policy_id} is not a held policy of stream {stream}")
        code = _refusal(policy_row, _key_roles_pin.resolve(repo.path))
        if code is not None:
            raise IngestError(f"{policy_id} may not take effect: {code}")
    policy = _ingest_policy.claim(policy_row["claim"])
    _refuse_optimizer(repo, key)
    previous = _ingest_holds.head(repo, stream)
    prior = _ingest_holds.read(repo, previous, CONVENTION) if previous else None
    if previous and prior is None:
        raise IngestError(f"stream {stream} head {previous} is unreadable")
    first = prior["claim"]["next_index"] if prior else 0
    if prior and prior["claim"].get("policy") != policy_row["id"]:
        before = _ingest_holds.read(repo, prior["claim"].get("policy"), _ingest_policy.CONVENTION)
        if before and str(before["claim"].get("issued_at")) >= policy["issued_at"]:
            raise IngestError(f"{policy_row['id']} is older than the policy stream {stream} "
                              "already uses")  # fmt: skip
    lines: list[bytes] = []
    dropped_by = {"kind": 0, "rate": 0}
    for offset, (kind, event) in enumerate(events):
        reason = _ingest_policy.decide(policy, first + offset, kind)
        if reason is None:
            line = {"e": event, "i": first + offset, "k": kind}
            lines.append(_LINE.encode(line).encode("utf-8") + b"\n")
        else:
            dropped_by[reason] += 1
    at = rfc3339_utc(at_ms / 1000)
    joined = b"".join(lines)
    with _write_batch.batched(repo):  # one durability point per batch
        target = _ingest_policy.anchor(repo, stream)
        claim = {"convention": CONVENTION, "stream": stream,
                 "seq": prior["claim"]["seq"] + 1 if prior else 0, "previous": previous,
                 "policy": policy_row["id"], "policy_digest": _ingest_policy.digest(policy),
                 "first_index": first, "next_index": first + len(events),
                 "received": len(events), "captured": len(lines),
                 "dropped": len(events) - len(lines), "dropped_by": dropped_by,
                 "input_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                 "events": (redact_blob(joined) if policy["redact"] else joined).decode(),
                 "at": at}  # fmt: skip
        oid = _ingest_holds.write(repo, target, claim, key, previous=previous, signed_at=at)
    _ingest_holds.move_head(repo, stream, previous, oid)  # only after the flush
    return {"id": oid, **{k: v for k, v in claim.items() if k != "events"}}


__all__ = ["CONVENTION", "MAX_EVENTS", "append", "current_policy", "parse"]
