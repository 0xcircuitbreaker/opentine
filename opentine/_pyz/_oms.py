"""OMS model signatures with the standard library (0.48, SPEC 4.26).

An independent port, for ``tine-verify.pyz``, of ``opentine._oms.check``: an
OpenSSF Model Signing v1.0 Sigstore bundle (DSSE, in-toto Statement v1,
``files`` serialization) verified with a pinned P-256 key, then its manifest
against ``{name: sha256 hex}`` of the model's files. Keyless bundles are
``oms.unsupported``: nothing here checks a Fulcio chain or a Rekor entry.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any

from . import _p256
from ._gitobj import Refused

TYPE = "application/vnd.in-toto+json"
LABEL = "model signature verified (OMS v1.0, pinned key)"


def _no(code: str, message: str) -> Refused:
    return Refused("oms." + code, message)


def _hex(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _unb64(value: Any, what: str) -> bytes:
    try:
        if isinstance(value, str):
            return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        pass
    raise _no("malformed", "OMS bundle is malformed: " + what + " is not base64")


def _resources(predicate: dict) -> list:
    rows, seen = [], set()
    items = predicate.get("resources")
    for item in items if isinstance(items, list) else [None]:
        ok = isinstance(item, dict) and item.get("algorithm") == "sha256"
        if not ok or not isinstance(item.get("name"), str) or not item["name"]:
            raise _no("malformed", "OMS payload is malformed: bad resource")
        if not _hex(item.get("digest")):
            raise _no("malformed", "OMS payload is malformed: bad resource")
        if item["name"] in seen:
            raise _no("malformed", "OMS payload is malformed: duplicate resource " + item["name"])
        seen.add(item["name"])
        rows.append((item["name"], item["digest"]))
    return sorted(rows)


def oms_verify(bundle: Any, files: Any, key_hex: Any) -> dict:
    env = bundle.get("dsseEnvelope") if isinstance(bundle, dict) else None
    if not isinstance(env, dict):
        raise _no("malformed", "OMS bundle is malformed: no dsseEnvelope")
    if not isinstance(env.get("signatures"), list) or not env["signatures"]:
        raise _no("malformed", "OMS bundle is malformed: no signatures")
    if len(env["signatures"]) > 16:
        raise _no("malformed", "OMS bundle is malformed: more than 16 signatures")
    if env.get("payloadType") != TYPE:
        raise _no("unsupported", "OMS bundle payloadType is not in-toto JSON")
    body = _unb64(env.get("payload"), "payload")
    vm = bundle.get("verificationMaterial")
    if isinstance(vm, dict) and ("certificate" in vm or "x509CertificateChain" in vm):
        raise _no("unsupported", "keyless OMS bundles (Fulcio certificate) are not verified here")
    if key_hex is None:
        raise _no("no-key", "no public key given for the OMS bundle")
    key = bytes.fromhex(key_hex)
    pae = b"DSSEv1 %d %s %d %s" % (len(TYPE), TYPE.encode(), len(body), body)
    sigs = [_unb64(s.get("sig") if isinstance(s, dict) else None, "signature")
            for s in env["signatures"]]  # fmt: skip
    if not any(_p256.verify(key, pae, sig) for sig in sigs):
        raise _no("bad-signature", "OMS bundle signature does not verify with the given key")
    try:
        st = json.loads(body.decode("utf-8"))
    except (RecursionError, UnicodeDecodeError, ValueError):
        raise _no("malformed", "OMS payload is malformed: not JSON") from None
    if not isinstance(st, dict) or st.get("_type") != "https://in-toto.io/Statement/v1":
        raise _no("malformed", "OMS payload is malformed: not an in-toto Statement v1")
    if st.get("predicateType") != "https://model_signing/signature/v1.0":
        raise _no("unsupported", "OMS predicateType is not model_signing v1.0")
    subs, pred = st.get("subject"), st.get("predicate")
    if not isinstance(subs, list) or len(subs) != 1 or not isinstance(pred, dict):
        raise _no("malformed", "OMS payload is malformed: one subject and a predicate")
    sub = subs[0] if isinstance(subs[0], dict) else {}
    root = sub.get("digest", {}).get("sha256") if isinstance(sub.get("digest"), dict) else None
    if not isinstance(sub.get("name"), str) or not _hex(root):
        raise _no("malformed", "OMS payload is malformed: bad subject")
    ser = pred.get("serialization")
    if not isinstance(ser, dict) or ser.get("method") != "files":
        raise _no("unsupported", "OMS serialization is not the 'files' method")
    if ser.get("hash_type", "sha256") != "sha256":
        raise _no("unsupported", "OMS hash_type is not sha256")
    skip = ser.get("ignore_paths") or []
    if not isinstance(skip, list) or any(not isinstance(p, str) for p in skip):
        raise _no("malformed", "OMS payload is malformed: bad ignore_paths")
    rows = _resources(pred)
    if hashlib.sha256(b"".join(bytes.fromhex(d) for _, d in rows)).hexdigest() != root:
        raise _no("root-mismatch", "OMS subject digest is not the digest of its resources")
    if files is not None:
        tops = [p.strip("/") for p in skip]
        have = {n: d for n, d in files.items()
                if not any(n == t or n.startswith(t + "/") for t in tops)}  # fmt: skip
        for name, digest in rows:
            if name not in have:
                raise _no("missing-file", "model file is missing: " + name)
            if have[name] != digest:
                raise _no("digest-mismatch", "model file does not match its signed digest: " + name)
        extra = sorted(set(have) - {n for n, _ in rows})
        if extra:
            raise _no("extra-file", "model file is not covered by the signature: " + extra[0])
    return {"model": sub["name"], "root_digest": "sha256:" + root, "files": len(rows),
            "key": "sha256:" + hashlib.sha256(key).hexdigest(), "state": "verified",
            "label": LABEL}  # fmt: skip


__all__ = ["oms_verify"]
