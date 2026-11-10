"""The six pre-cutoff document kinds that had no vectors until 0.50, in the pyz.

``tine-verify-report/2`` (SPEC 8.7), exported ``tine-custody/1`` records (8.4),
the DSSE-signed in-toto ``replay/v1`` statement (8.8), the ``TINEAES6`` header
(Part 11, no decryption: the pyz never holds a tenant key),
``opentine-line-attribution/1`` (8.24) and ``tine-cost-statement/1`` (8.25).
Ports of ``_verify_report_sign.check``, ``_custody.check_records``,
``_intoto_replay.verify_envelope``, ``remote._sealed6.parse_header``,
``_line_attrib.verify_lines`` and ``_cost_export.verify_against``; the
``tine-sig/3`` verdict is :func:`._conform_sig.verify_block`. Refusals are
:class:`Refused` with the vectors' reason codes.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .. import kernel
from . import _conform_replay, _conform_sig, _ed25519
from ._gitobj import Refused

REPORT_DOMAIN = b"opentine.verify-report.v2:"
CUSTODY_DOMAIN = b"opentine.custody.v1:"
LINES_DOMAIN = b"opentine.line-attribution.v1:"
COST_DOMAIN = b"opentine.cost-statement.v1:"
CUSTODY = "opentine-custody/1"
SEALED6 = b"TINEAES6"


def _key(value: dict) -> bytes | None:
    return bytes.fromhex(value["public_key"]) if value.get("public_key") else None


def signed_doc(domain: bytes, body: dict, block: Any, public_key: bytes | None) -> dict:
    """``_signed_doc.verify``: Ed25519 ``tine-sig/3``; no key trusts the embedded one."""
    if isinstance(block, dict) and block.get("alg") != "ed25519":
        return dict(zip(_conform_sig.FIELDS, (False, "error", None, None, None, None,
                                               "Ed25519 only")))  # fmt: skip
    keys = {"hmac_key": None, "public_key": public_key, "trust_embedded": public_key is None}

    def message(header: dict) -> bytes:
        view = {"body": body, "header": {k: header.get(k) for k in _conform_sig.HEADER_KEYS}}
        return domain + kernel.canonical_json(view)

    return _conform_sig.verify_block(block, message, ("tine-sig/3",), "document", keys)


def basis(block: Any, public_key: bytes | None) -> str:
    raw = block.get("public_key") if isinstance(block, dict) else None
    try:
        found = (
            "sha256:" + hashlib.sha256(bytes.fromhex(raw)).hexdigest()
            if isinstance(raw, str)
            else "?"
        )
    except ValueError:
        found = "?"
    return (
        f"supplied key {found}"
        if public_key is not None
        else f"embedded key {found} (trust on first use)"
    )


def bound(block: Any) -> str:
    return "sig:sha256:" + hashlib.sha256(kernel.canonical_json(block)).hexdigest()


def verify_report(raw: Any, value: dict, args: dict) -> dict:
    doc, key = value["report"], _key(value)
    result: dict[str, Any] = {
        "schema": doc.get("schema"), "report_verdict": doc.get("verdict"),
        "path": doc.get("path"), "signed": "signature" in doc,
        "signature": None, "timestamps": [], "signing_time": None,
    }  # fmt: skip
    if doc.get("schema") == "tine-verify-report/1" or "signature" not in doc:
        return {**result, "evidence": False, "ok": False, "reason": "report.unsigned"}
    if doc.get("signature_timestamps"):
        raise Refused(
            "verify-report.timestamps-unsupported", "RFC 3161 tokens are not checked here"
        )
    body = {k: v for k, v in doc.items() if k not in ("signature", "signature_timestamps")}
    verdict = signed_doc(REPORT_DOMAIN, body, doc["signature"], key)
    result["signature"] = {
        name: verdict[name] for name in ("ok", "state", "reason", "signer", "signed_at")
    }
    result["signature"]["trust_basis"] = basis(doc["signature"], key)
    ok = verdict["ok"]
    reason = "report.verified" if ok else "report.signature-invalid"
    return {**result, "evidence": ok, "ok": ok, "reason": reason}


def custody_chain(raw: Any, value: dict, args: dict) -> dict:
    records, key = value["records"], _key(value)
    if not isinstance(records, list):
        raise Refused("custody.malformed", "custody records must be a list")
    out, prev = [], None
    for index, rec in enumerate(records):
        if not isinstance(rec, dict) or rec.get("format") != CUSTODY:
            raise Refused("custody.malformed", f"custody record {index} is not an {CUSTODY} record")
        if rec.get("prev") != prev:
            raise Refused("custody.chain-broken", f"custody record {index} breaks the hash chain")
        body = {k: v for k, v in rec.items() if k != "signature"}
        verdict = signed_doc(CUSTODY_DOMAIN, body, rec.get("signature"), key)
        if not verdict["ok"]:
            message = f"custody record {index}: signature {verdict['reason']}"
            raise Refused("custody.bad-signature", message)
        prev = hashlib.sha256(b"\x00" + kernel.canonical_json(rec)).hexdigest()
        out.append({"index": index, "action": rec.get("action"), "subject": rec.get("subject"),
                    "signer": verdict["signer"], "state": verdict["state"],
                    "sig_bound": bound(rec["signature"])})  # fmt: skip
    return {"size": len(out), "records": out, "head": prev}


def custody_record(raw: Any, value: dict, args: dict) -> dict:
    """``_evidence_export.verify_custody``: a ``tine-custody/1`` record under its own key."""
    record = value["record"]
    block = record.get("signature")
    valid = False
    if isinstance(block, dict):
        body = {k: v for k, v in record.items() if k != "signature"}
        try:
            key, sig = bytes.fromhex(block["public_key"]), bytes.fromhex(block["value"])
            valid = _ed25519.verify(key, CUSTODY_DOMAIN + kernel.canonical_json(body), sig)
        except (KeyError, TypeError, ValueError):
            valid = False
    return {"schema": record.get("schema"), "manifest_sha256": record.get("manifest_sha256"),
            "signed": isinstance(block, dict), "valid": valid}  # fmt: skip


def sealed6_header(raw: Any, value: Any, args: dict) -> dict:
    """``remote._sealed6.parse_header``: magic, key id, epoch, flags, codec, size."""
    bad = Refused("sealed6.malformed", "invalid encrypted object header")
    if not raw.startswith(SEALED6) or len(raw) < len(SEALED6) + 1:
        raise bad
    at = len(SEALED6) + 1
    end = at + raw[len(SEALED6)]
    if end + 14 + 24 + 16 > len(raw) or end == at:
        raise bad
    try:
        key_id = raw[at:end].decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise Refused("sealed6.malformed", "the key id is not ASCII") from exc
    flags = raw[end + 4]
    if flags & ~0x01:
        raise Refused("sealed6.malformed", "encrypted object has unknown flags")
    return {"key_id": key_id, "epoch": int.from_bytes(raw[end : end + 4], "big"), "flags": flags,
            "codec": raw[end + 5], "size": int.from_bytes(raw[end + 6 : end + 14], "big"),
            "header_length": end + 14}  # fmt: skip


def _lines_hash(lines: list[str]) -> str:
    return "sha256:" + hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def line_attribution(raw: Any, value: dict, args: dict) -> dict:
    record, key = value["record"], _key(value)
    added = {
        path: {int(n): text for n, text in rows.items()} for path, rows in value["added"].items()
    }
    stale = []
    for entry in record.get("files") or []:
        lines = added.get(entry.get("path"), {})
        for item in entry.get("ranges") or []:
            span = range(int(item["start_line"]), int(item["end_line"]) + 1)
            if any(n not in lines for n in span) or (
                _lines_hash([lines[n] for n in span]) != item.get("content_hash")
            ):
                stale.append(f"{entry.get('path')}:{span.start}-{span.stop - 1}")
    signature: dict[str, Any] = {"present": isinstance(record.get("signature"), dict)}
    if signature["present"]:
        body = {k: v for k, v in record.items() if k != "signature"}
        verdict = signed_doc(LINES_DOMAIN, body, record["signature"], key)
        signature.update(valid=bool(verdict["ok"]), state=verdict["state"],
                         basis=basis(record["signature"], key))  # fmt: skip
    return {"signature": signature, "content_matches": not stale, "stale_ranges": stale}


def cost_statement(raw: Any, value: dict, args: dict) -> dict:
    doc, key = value["statement"], _key(value)
    body = {k: v for k, v in doc.items() if k != "signature"}
    matches = body == value["expected"]
    block = doc.get("signature")
    if not isinstance(block, dict):
        return {"ok": False, "matches_run": matches, "signature": "unsigned", "basis": None}
    verdict = signed_doc(COST_DOMAIN, body, block, key)
    return {"ok": bool(matches and verdict["ok"]), "matches_run": matches,
            "signature": "verified" if verdict["ok"] else verdict["state"],
            "basis": basis(block, key) if verdict["ok"] else None}  # fmt: skip


OPS = {
    "verify-report.verify": verify_report,
    "custody.chain": custody_chain,
    "custody.record": custody_record,
    "replay.verify": _conform_replay.replay_verify,
    "sealed6.header": sealed6_header,
    "line-attribution.verify": line_attribution,
    "cost-statement.verify": cost_statement,
}

__all__ = ["OPS", "Refused"]
