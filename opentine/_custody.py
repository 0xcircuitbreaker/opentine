"""Chain of custody on ``opentine-log/1`` (0.39, ROADMAP §7).

Each custody record is one entry of the log at ``.tine/log/custody``, the same
C2SP tlog-tiles layout and signed-note checkpoint the op log uses
(:mod:`opentine.repository._oplog`), so a record cannot be edited, dropped or
reordered without the checkpoint's Merkle root going wrong. On top of that:

* a hash chain: ``prev`` is the previous entry's leaf hash, as in the op log;
* a signature: every record carries an Ed25519 ``tine-sig/3`` block
  (``_signed_doc``, domain ``opentine.custody.v1:``) over all its other members,
  made with the *actor's* key, not the log's checkpoint key -- so the record says
  who received, exported or verified what, and that person signed it;
* optional time: a later ``timestamp`` record carries an RFC 3161 token whose
  messageImprint covers ``sig:sha256:<hex>`` of an earlier record's signature
  block (X20). Its genTime is that record's verified signing time.

:func:`verify` re-checks all four offline and fails on the first broken one.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine import _signed_doc
from opentine._timestamp_sidecar import signature_bound
from opentine.kernel import canonical_json
from opentine.repository import _tlog, _tlog_note
from opentine.repository._paths import internal_path

FORMAT = "opentine-custody/1"
ORIGIN = "opentine.local/log/custody"
DOMAIN = b"opentine.custody.v1:"
ACTIONS = ("received", "exported", "verified", "transferred", "stored", "timestamp")
MAX_TOKEN = 16 * 1024


def log_root(base: Path) -> Path:
    return internal_path(Path(base), "log", "custody")


def record(
    base: Path,
    action: str,
    subject: str,
    private_key: Any,
    *,
    actor: str,
    note: str = "",
    token: bytes | None = None,
) -> dict[str, Any]:
    """Append one signed record; return it. ``timestamp`` records need *token*."""
    if action not in ACTIONS:
        raise ValueError(f"unknown custody action {action!r}; one of {', '.join(ACTIONS)}")
    if (action == "timestamp") != (token is not None):
        raise ValueError("a timestamp record, and only one, carries --token")
    if token is not None:
        _check_token(base, subject, token)
    body: dict[str, Any] = {
        "action": action,
        "actor": actor,
        "format": FORMAT,
        "id": secrets.token_hex(8),
        "note": note,
        "subject": subject,
        "time": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if token is not None:
        body["token"] = base64.b64encode(token).decode("ascii")
    made: dict[str, Any] = {}

    def chained(entries: list[bytes]) -> bytes:
        full = {**body, "prev": _tlog.leaf_hash(entries[-1]).hex() if entries else None}
        full["signature"] = _signed_doc.sign(DOMAIN, full, private_key, signer=actor)
        made.update(full)
        return canonical_json(full)

    index = _tlog_note.append(log_root(base), ORIGIN, chained)
    return {**made, "index": index, "sig_bound": signature_bound(made["signature"])}


def _check_token(base: Path, subject: str, token: bytes) -> None:
    from opentine._tsp import HASHES, parse

    if len(token) > MAX_TOKEN:
        raise ValueError(f"a custody token is at most {MAX_TOKEN} bytes")
    if subject not in {r["sig_bound"] for r in read(base)}:
        raise ValueError(f"{subject} is not the signature binding of a custody record")
    parsed = parse(token)
    if parsed.hash_oid not in HASHES:
        raise ValueError(f"unsupported imprint hash {parsed.hash_oid}")
    if hashlib.new(parsed.hash_name, subject.encode("utf-8")).digest() != parsed.imprint:
        raise ValueError(f"the token does not cover {subject}")


def read(base: Path, vkey: str | None = None) -> list[dict[str, Any]]:
    """Every record, oldest first, from a verified log with an unbroken hash chain."""
    entries = _tlog_note.verify_log(log_root(base), ORIGIN, vkey)
    out, prev = [], None
    for index, entry in enumerate(entries):
        try:
            rec = json.loads(entry)
        except ValueError as exc:
            raise _tlog.LogError(f"custody record {index} is not JSON") from exc
        if not isinstance(rec, dict) or rec.get("format") != FORMAT:
            raise _tlog.LogError(f"custody record {index} is not an {FORMAT} record")
        if rec.get("prev") != prev:
            raise _tlog.LogError(f"custody record {index} breaks the hash chain")
        prev = _tlog.leaf_hash(entry).hex()
        try:
            bound = signature_bound(rec.get("signature"))
        except ValueError as exc:
            raise _tlog.LogError(f"custody record {index} has no signature") from exc
        out.append({**rec, "index": index, "sig_bound": bound})
    return out


def verify(
    base: Path, args: Any, *, vkey: str | None = None, public_key: Any | None = None
) -> dict[str, Any]:
    """Log, chain, every signature and every token; ``LogError`` on the first failure."""
    from opentine._tsp_verify import verify_token
    from opentine._verify_timestamp import _roots

    records = read(base, vkey)
    times: dict[str, str] = {}
    roots: Any = None
    for rec in records:
        body = {k: v for k, v in rec.items() if k not in ("signature", "index", "sig_bound")}
        verdict = _signed_doc.verify(DOMAIN, body, rec["signature"], public_key=public_key)
        if not verdict.ok:
            raise _tlog.LogError(f"custody record {rec['index']}: signature {verdict.reason}")
        if rec["action"] != "timestamp":
            continue
        if roots is None:
            roots = _roots(args)
        try:
            raw = base64.b64decode(rec.get("token", ""), validate=True)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise _tlog.LogError(f"custody record {rec['index']}: malformed token") from exc
        stamp = verify_token(raw, rec["subject"].encode("utf-8"), roots[0], roots[1])
        if not stamp.ok and not stamp.no_roots:
            raise _tlog.LogError(f"custody record {rec['index']}: {stamp.detail}")
        if stamp.ok:
            times.setdefault(rec["subject"], stamp.info["gen_time"])
    for rec in records:
        if rec["sig_bound"] in times:
            rec["signing_time"] = times[rec["sig_bound"]]
    vkey_used = vkey or (_tlog_note.stored_vkey(log_root(base)) if records else None)
    basis = "supplied key" if public_key is not None else "embedded keys (trust on first use)"
    return {"ok": True, "records": records, "size": len(records), "vkey": vkey_used, "basis": basis}


__all__ = ["ACTIONS", "FORMAT", "ORIGIN", "log_root", "read", "record", "verify"]
