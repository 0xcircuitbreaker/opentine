"""The ``digest`` and ``signature`` checks of ``tine verify --offline``, for one file.

A format v4 file (SPEC Part 9; a v5 file, Part 10, as the v4 document it spells)
is checked with the vendored kernel exactly as
``opentine._artifact_v4_read`` does: the document has exactly the v4 keys and
bounded lists, every envelope is rebuilt from its v4 spelling and decoded by
``kernel.ObjectEnvelope.decode`` against its oid, objects are only blobs,
events and runs, the root is a run the file carries, ``kernel.validate_links``
walks a closure that must reach every object, and annotations form one chain
on the root, oldest first. A v2 file's digest is SHA-256 over the canonical
body without ``metadata`` (SPEC 3.5). Reason codes are the report's own.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any

from .. import _tine_v5, kernel
from . import _load, _sig

V4_KIND = "tine-artifact/4"
V4_KEYS = frozenset({"annotations", "format_version", "kind", "objects", "root", "signatures"})
MAX_V4_OBJECTS, MAX_V4_ANNOTATIONS, MAX_V4_SIGNATURES = 1_000_000, 1024, 16
SUPPORTED = (1, 2)
_HEADER = ("encoding", "schema", "type")
_BUNDLED = frozenset({"blob", "event", "run"})


def check(name: str, outcome: str, reason: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {"name": name, "outcome": outcome, "reason": reason, "detail": detail, **extra}


def is_v4(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and type(data.get("format_version")) is int
        and data.get("format_version") == 4
        and data.get("kind") == V4_KIND
    )


def _envelope(entry: Any, oid: Any, where: str) -> kernel.ObjectEnvelope:
    if not isinstance(entry, dict) or not isinstance(oid, str):
        raise ValueError(f"{where}: malformed v4 envelope")
    raw = entry.get("encoding") == "raw"
    if set(entry) != {*_HEADER, "data" if raw else "body"}:
        raise ValueError(f"{where}: a v4 envelope is encoding, schema, type and data|body")
    try:
        if raw:
            text = entry["data"]
            body = base64.b64decode(text.encode("ascii"), validate=True)
            if base64.b64encode(body).decode("ascii") != text:
                raise ValueError("blob data is not canonical base64")
        else:
            dumped = json.dumps(entry["body"], allow_nan=False)
            body = kernel.canonical_json(json.loads(dumped, parse_int=kernel._parse_int))
        header = kernel.canonical_json({name: entry[name] for name in _HEADER})
        return kernel.ObjectEnvelope.decode(header + b"\n" + body, oid)
    except (AttributeError, binascii.Error, RecursionError, UnicodeError, ValueError) as exc:
        raise ValueError(f"{where}: {exc}") from exc


def _closure(objects: dict[str, kernel.ObjectEnvelope], root: str) -> int:
    seen, stack = {root}, [root]
    while stack:
        for link in kernel.validate_links(objects[stack.pop()]):
            if link in seen:
                continue
            if link not in objects:
                raise ValueError(f"v4 artifact is missing linked object {link}")
            seen.add(link)
            stack.append(link)
    return len(seen)


def read_v4(data: dict[str, Any]) -> str:
    """The root of a v4 document, or ``ValueError`` naming what does not verify."""
    if set(data) != V4_KEYS:
        raise ValueError(f"v4 artifact keys must be exactly {sorted(V4_KEYS)}")
    if not isinstance(data["objects"], dict) or len(data["objects"]) > MAX_V4_OBJECTS:
        raise ValueError(f"v4 objects must be a map of at most {MAX_V4_OBJECTS} envelopes")
    annotations = data["annotations"]
    if not isinstance(annotations, list) or len(annotations) > MAX_V4_ANNOTATIONS:
        raise ValueError(f"v4 annotations must be a list of at most {MAX_V4_ANNOTATIONS}")
    signatures = data["signatures"]
    if not isinstance(signatures, list) or len(signatures) > MAX_V4_SIGNATURES:
        raise ValueError(f"v4 signatures must be a list of at most {MAX_V4_SIGNATURES}")
    if any(not isinstance(b, dict) or b.get("scheme") != "tine-sig/3" for b in signatures):
        raise ValueError("every v4 signature must be a tine-sig/3 block")
    root = data["root"]
    objects: dict[str, kernel.ObjectEnvelope] = {}
    for oid, entry in data["objects"].items():
        if kernel.parse_oid(oid)[0] not in _BUNDLED:
            raise ValueError(f"v4 objects hold only blob, event and run envelopes: {oid}")
        objects[oid] = _envelope(entry, oid, f"objects[{oid}]")
    if not isinstance(root, str) or kernel.parse_oid(root)[0] != "run" or root not in objects:
        raise ValueError("v4 root must name a run envelope the artifact carries")
    if _closure(objects, root) != len(objects):
        raise ValueError("v4 artifact carries objects its root does not reach")
    previous = None
    for index, entry in enumerate(annotations):
        where = f"annotations[{index}]"
        body = {k: v for k, v in entry.items() if k != "id"} if isinstance(entry, dict) else None
        envelope = _envelope(body, entry.get("id") if body is not None else None, where)
        payload = envelope.payload()
        if envelope.object_type != "annotation" or payload.get("target_id") != root:
            raise ValueError(f"{where}: must be an annotation of the root run")
        if payload.get("previous_id") != previous:
            raise ValueError(f"{where}: annotations must form one chain, oldest first")
        kernel.validate_links(envelope)
        previous = envelope.oid
    return root


def _v2_digest(data: dict[str, Any]) -> tuple[bool, str, str]:
    """``(ok, reason code, detail)`` of ``_graph_serde.verify_integrity`` on a v2 file."""
    version = data.get("format_version")
    if type(version) is not int or version not in SUPPORTED:
        return False, "digest.unsupported-format", f"unsupported .tine format_version={version!r}"
    meta = data.get("metadata")
    block = meta.get("integrity") if isinstance(meta, dict) else None
    if not isinstance(block, dict):
        return False, "digest.missing", "missing integrity digest"
    if block.get("algorithm") != "sha256":
        return False, "digest.unsupported-algorithm", "unsupported algorithm"
    expected = block.get("digest")
    try:
        well_formed = isinstance(expected, str) and len(expected) == 64 and int(expected, 16) >= 0
    except ValueError:
        well_formed = False
    if not well_formed:
        return False, "digest.malformed", "malformed digest"
    try:
        actual = hashlib.sha256(_sig.canon_v2({k: v for k, v in data.items() if k != "metadata"}))
    except (RecursionError, TypeError, ValueError):
        return False, "digest.mismatch", f"digest mismatch (expected {expected})"
    if actual.hexdigest() != expected:
        detail = f"digest mismatch (expected {expected}, actual {actual.hexdigest()})"
        return False, "digest.mismatch", detail
    return True, "digest.match", f"sha256:{expected}"


def digest_check(path: Path) -> tuple[dict[str, Any], Any]:
    """The ``digest`` check and the parsed document (``None`` if it did not parse)."""
    try:
        data = _load.read(path)
    except _load.ZstdRefused as exc:
        return check("digest", "fail", "digest.zstd-unsupported", str(exc), required=True), None
    except FileNotFoundError:
        return check("digest", "fail", "digest.unreadable", "file not found", required=True), None
    except OSError as exc:
        detail = f"read error: {exc}"
        return check("digest", "fail", "digest.unreadable", detail, required=True), None
    except (RecursionError, ValueError) as exc:
        detail = f"invalid artifact: {exc}"
        return check("digest", "fail", "artifact.malformed-json", detail, required=True), None
    if not isinstance(data, dict):
        detail = "artifact root is not an object"
        return check("digest", "fail", "digest.unreadable", detail, required=True), None
    if _tine_v5.is_v5_artifact(data):  # SPEC Part 10: checked as the v4 document it spells
        try:
            data = _tine_v5.to_v4(data)
        except ValueError as exc:
            detail = f"invalid v5 artifact: {exc}"
            return check("digest", "fail", "digest.mismatch", detail, required=True), data
    if is_v4(data):
        try:
            root = read_v4(data)
        except (KeyError, RecursionError, TypeError, ValueError) as exc:
            detail = f"invalid v4 artifact: {exc}"
            return check("digest", "fail", "digest.mismatch", detail, required=True), data
        return check("digest", "pass", "digest.match", f"root {root}", required=True), data
    ok, reason, detail = _v2_digest(data)
    return check("digest", "pass" if ok else "fail", reason, detail, required=True), data


def signature_check(
    data: Any, digest_ok: bool, *, hmac_key: bytes | None, public_key: bytes | None
) -> dict[str, Any]:
    """``_verify_offline.signature_check``'s outcomes for the keys this verifier takes."""
    if not digest_ok or not isinstance(data, dict):
        return check(
            "signature", "not-applicable", "signature.integrity-failed",
            "not checked: the digest already failed", required=True,
        )  # fmt: skip
    v4 = is_v4(data)
    if hmac_key is None and public_key is None:
        state = _sig.artifact_verdict(data, v4, hmac_key=None, public_key=None)[1]
        if state == "unsigned":
            detail, reason = "the run carries no signature", "signature.unsigned"
        else:
            detail = "signature present but no trusted key was given: pass --pubkey or --key-file"
            reason = "signature.no-key"
        return check("signature", "unavailable-offline", reason, detail, required=True)
    ok, state, why = _sig.artifact_verdict(data, v4, hmac_key=hmac_key, public_key=public_key)
    if ok:
        return check("signature", "pass", f"signature.{state}", why, required=True)
    outcome = "unavailable-offline" if state in ("no-key", "unsigned") else "fail"
    return check("signature", outcome, f"signature.{state}", why, required=True)


__all__ = ["check", "digest_check", "is_v4", "read_v4", "signature_check"]
