"""OMS model-signature checks: an assurance factor (0.48, SPEC 4.26).

The OpenSSF Model Signing format (OMS, ``model_signing`` 1.x / sigstore
model-transparency) signs a model as a Sigstore bundle whose DSSE envelope
carries an in-toto Statement v1 with predicate type
``https://model_signing/signature/v1.0``: one ``resources`` entry
``{name, algorithm, digest}`` per model file (POSIX path relative to the model
root) and one subject whose ``sha256`` digest is SHA-256 over the raw resource
digests concatenated in name order.

:func:`check` verifies the key-based form (``model_signing`` ``key`` method,
ECDSA P-256 over the DSSE pre-authentication encoding) against a pinned public
key, then the manifest against the model's files. Keyless (certificate) bundles
are refused as ``oms.unsupported``: their Fulcio chain and Rekor entry are not
checked here, and an unchecked factor is never reported as verified.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from opentine._pyz import _p256
from opentine._signed_record import RecordError

PREDICATE = "https://model_signing/signature/v1.0"
STATEMENT = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
LABEL = "model signature verified (OMS v1.0, pinned key)"
FACTOR = "oms-model-signature"
_HEX64 = re.compile(r"[0-9a-f]{64}")
#: Files a directory walk reads before it refuses (a model is many files, not millions).
MAX_FILES = 100_000
#: DSSE signatures one bundle may carry (each costs a pure-Python ECDSA verify).
MAX_SIGNATURES = 16


def _no(code: str, message: str) -> RecordError:
    return RecordError("oms." + code, message)


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def _b64(value: Any, what: str) -> bytes:
    if not isinstance(value, str):
        raise _no("malformed", f"OMS bundle is malformed: {what} is not base64")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _no("malformed", f"OMS bundle is malformed: {what} is not base64") from exc


def _envelope(bundle: Any) -> tuple[dict[str, Any], bytes]:
    if not isinstance(bundle, dict) or not isinstance(bundle.get("dsseEnvelope"), dict):
        raise _no("malformed", "OMS bundle is malformed: no dsseEnvelope")
    envelope = bundle["dsseEnvelope"]
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise _no("malformed", "OMS bundle is malformed: no signatures")
    if len(signatures) > MAX_SIGNATURES:
        raise _no("malformed", f"OMS bundle is malformed: more than {MAX_SIGNATURES} signatures")
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise _no("unsupported", "OMS bundle payloadType is not in-toto JSON")
    return envelope, _b64(envelope.get("payload"), "payload")


def _signed(bundle: dict[str, Any], envelope: dict[str, Any], payload: bytes, key: Any) -> str:
    material = bundle.get("verificationMaterial")
    if isinstance(material, dict) and (
        "certificate" in material or "x509CertificateChain" in material
    ):
        raise _no("unsupported", "keyless OMS bundles (Fulcio certificate) are not verified here")
    if key is None:
        raise _no("no-key", "no public key given for the OMS bundle (pass --model-pubkey)")
    message = pae(PAYLOAD_TYPE, payload)
    entries = envelope["signatures"]
    sigs = [_b64(e.get("sig") if isinstance(e, dict) else None, "signature") for e in entries]
    if any(_p256.verify(key, message, sig) for sig in sigs):
        return "sha256:" + hashlib.sha256(key).hexdigest()
    raise _no("bad-signature", "OMS bundle signature does not verify with the given key")


def _statement(payload: bytes) -> tuple[str, str, list[tuple[str, str]], list[str]]:
    try:
        statement = json.loads(payload.decode("utf-8"))
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise _no("malformed", "OMS payload is malformed: not JSON") from exc
    if not isinstance(statement, dict) or statement.get("_type") != STATEMENT:
        raise _no("malformed", "OMS payload is malformed: not an in-toto Statement v1")
    if statement.get("predicateType") != PREDICATE:
        raise _no("unsupported", "OMS predicateType is not model_signing v1.0")
    subjects, predicate = statement.get("subject"), statement.get("predicate")
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(predicate, dict):
        raise _no("malformed", "OMS payload is malformed: one subject and a predicate")
    subject = subjects[0] if isinstance(subjects[0], dict) else {}
    digest = (
        (subject.get("digest") or {}).get("sha256")
        if isinstance(subject.get("digest"), dict)
        else None
    )
    if (
        not isinstance(subject.get("name"), str)
        or not isinstance(digest, str)
        or not _HEX64.fullmatch(digest)
    ):
        raise _no("malformed", "OMS payload is malformed: bad subject")
    serialization = predicate.get("serialization")
    if not isinstance(serialization, dict) or serialization.get("method") != "files":
        raise _no("unsupported", "OMS serialization is not the 'files' method")
    if serialization.get("hash_type", "sha256") != "sha256":
        raise _no("unsupported", "OMS hash_type is not sha256")
    ignored = serialization.get("ignore_paths") or []
    if not isinstance(ignored, list) or not all(isinstance(p, str) for p in ignored):
        raise _no("malformed", "OMS payload is malformed: bad ignore_paths")
    resources, names = [], set()
    for item in (
        predicate.get("resources") if isinstance(predicate.get("resources"), list) else [None]
    ):
        if not isinstance(item, dict) or item.get("algorithm") != "sha256":
            raise _no("malformed", "OMS payload is malformed: bad resource")
        name, value = item.get("name"), item.get("digest")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(value, str)
            or not _HEX64.fullmatch(value)
        ):
            raise _no("malformed", "OMS payload is malformed: bad resource")
        if name in names:
            raise _no("malformed", "OMS payload is malformed: duplicate resource " + name)
        names.add(name)
        resources.append((name, value))
    return subject["name"], digest, sorted(resources), ignored


def _ignored(name: str, ignored: list[str]) -> bool:
    return any(
        name == path.strip("/") or name.startswith(path.strip("/") + "/") for path in ignored
    )


def check(bundle: Any, files: dict[str, str] | None, public_key: Any) -> dict[str, Any]:
    """Verify an OMS bundle over a model's ``{posix name: sha256 hex}``; ``RecordError`` if not."""
    envelope, payload = _envelope(bundle)
    key = _signed(bundle, envelope, payload, public_key)
    model, root, resources, ignored = _statement(payload)
    computed = hashlib.sha256(b"".join(bytes.fromhex(d) for _, d in resources)).hexdigest()
    if computed != root:
        raise _no("root-mismatch", "OMS subject digest is not the digest of its resources")
    if files is not None:
        present = {name: d for name, d in files.items() if not _ignored(name, ignored)}
        for name, digest in resources:
            if name not in present:
                raise _no("missing-file", "model file is missing: " + name)
            if present[name] != digest:
                raise _no("digest-mismatch", "model file does not match its signed digest: " + name)
        extra = sorted(set(present) - {name for name, _ in resources})
        if extra:
            raise _no("extra-file", "model file is not covered by the signature: " + extra[0])
    return {"model": model, "root_digest": "sha256:" + root, "files": len(resources),
            "key": key, "state": "verified", "label": LABEL}  # fmt: skip


def digest_dir(root: str | Path, skip: tuple[Path, ...] = ()) -> dict[str, str]:
    """``{posix relative name: sha256 hex}`` of every regular file under ``root``."""
    base = Path(root)
    if base.is_file():
        return {base.name: hashlib.sha256(base.read_bytes()).hexdigest()}
    out: dict[str, str] = {}
    skipped = {p.resolve() for p in skip}
    for path in sorted(base.rglob("*")):
        if path.is_symlink():
            raise _no("unsupported", "model holds a symlink: " + path.relative_to(base).as_posix())
        if not path.is_file() or path.resolve() in skipped:
            continue
        if len(out) >= MAX_FILES:
            raise _no("malformed", f"model holds more than {MAX_FILES} files")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
        out[path.relative_to(base).as_posix()] = digest.hexdigest()
    return out


__all__ = ["FACTOR", "LABEL", "PREDICATE", "check", "digest_dir", "pae"]
