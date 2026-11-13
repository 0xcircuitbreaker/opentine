"""Browser trust bundles (0.51, SPEC 8.26): owner-signed trust configuration.

A trust bundle lets a viewer (``tine ui``, opentine-web) pin run signers
without a local ``trust-policies.json``. It is a profile of formats that
already exist, not a new kind: a C2SP signed note (the checkpoint format of
SPEC 8.10) signed by the bundle owner's Ed25519 key, whose text is::

    <owner key name>
    <canonical JSON payload>

and whose payload holds only existing documents::

    {"trust_bundle": 1, "serial": N, "issued_at": T, ["expires_at": T,]
     "trust_policy": {...},            # a trust-policies.json entry, portable fields
     ["witness_network": {...},]       # an opentine-witness-network/1 registry
     ["log_keys": [vkey, ...],]        # pinned signed-note log keys
     ["admission_policies": {name: {...}}]}  # opentine.admission-policy documents

Every part is checked by the validator of its own format. Path fields of a
trust policy (``pubkey``, ``rekor_key``, ...) name local files and are
refused: a bundle carries key fingerprints (``pin``), never paths. A reader
pins the owner's verifier key (``name+hash+key``) out of band, refuses a
bundle that key did not sign, one past ``expires_at``, and, once it has seen
serial N, any bundle with a lower serial (rollback).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from opentine.kernel import _parse_int, canonical_json

MAX_BYTES = 1 << 20
_DASH = "— "
_TOP = {
    "trust_bundle",
    "serial",
    "issued_at",
    "expires_at",
    "trust_policy",
    "witness_network",
    "log_keys",
    "admission_policies",
}
#: Trust-policy fields a bundle may carry: no local paths.
PORTABLE = ("pin", "require_receipt", "cert_identity", "cert_oidc_issuer", "require_sct",
            "key_lifecycle")  # fmt: skip
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")
MAX_LOG_KEYS = 64
MAX_ADMISSION = 64


class BundleError(ValueError):
    """A trust bundle that is malformed, unsigned by the pinned owner or stale."""


def _time(value: Any, what: str) -> datetime:
    parsed = None
    if isinstance(value, str) and _RFC3339.fullmatch(value):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
    if parsed is None:
        raise BundleError(f"trust bundle: {what} must be an RFC 3339 time with an offset")
    return parsed


def _policy(value: Any) -> dict[str, Any]:
    from opentine._trust_policy import PolicyError, check_policy

    if not isinstance(value, dict) or set(value) - set(PORTABLE):
        raise BundleError(f"trust bundle: trust_policy may only hold {', '.join(PORTABLE)}")
    from opentine._signing_keys import SignatureError

    try:
        check_policy("bundle", value)
    except (PolicyError, SignatureError) as exc:
        raise BundleError(f"trust bundle: {exc}") from None
    pins = value.get("pin", [])
    if any(not str(pin).startswith("sha256:") or pin != pin.lower() for pin in pins):
        raise BundleError("trust bundle: pin must list sha256:<64 lowercase hex> fingerprints")
    return value


def _log_keys(value: Any) -> list[str]:
    from opentine.repository._tlog import LogError
    from opentine.repository._tlog_note import parse_vkey

    if not isinstance(value, list) or len(value) > MAX_LOG_KEYS:
        raise BundleError(f"trust bundle: log_keys must list at most {MAX_LOG_KEYS} keys")
    for vkey in value:
        try:
            parse_vkey(vkey if isinstance(vkey, str) else "")
        except LogError as exc:
            raise BundleError(f"trust bundle: log key: {exc}") from None
    return value


def _admission(value: Any) -> dict[str, Any]:
    from opentine.remote._admission_policy import parse_policy

    if not isinstance(value, dict) or len(value) > MAX_ADMISSION:
        raise BundleError(f"trust bundle: admission_policies must map at most {MAX_ADMISSION}")
    for name, doc in value.items():
        try:
            parse_policy(name, json.dumps(doc).encode("utf-8"))
        except Exception as exc:  # noqa: BLE001 -- the policy's own error, re-labelled
            raise BundleError(f"trust bundle: admission policy {name!r}: {exc}") from None
    return value


def validate(payload: Any) -> dict[str, Any]:
    """*payload* if every part passes its own format's validator; BundleError otherwise."""
    if not isinstance(payload, dict) or set(payload) - _TOP or payload.get("trust_bundle") != 1:
        raise BundleError("not a trust bundle payload (trust_bundle: 1)")
    serial = payload.get("serial")
    if not isinstance(serial, int) or isinstance(serial, bool) or not 1 <= serial < 2**53:
        raise BundleError("trust bundle: serial must be a positive integer")
    issued = _time(payload.get("issued_at"), "issued_at")
    if "expires_at" in payload and _time(payload["expires_at"], "expires_at") <= issued:
        raise BundleError("trust bundle: expires_at must be after issued_at")
    _policy(payload.get("trust_policy"))
    if "witness_network" in payload:
        from opentine import _witness_network
        from opentine.repository._tlog import LogError

        try:
            _witness_network.validate(payload["witness_network"])
        except LogError as exc:
            raise BundleError(f"trust bundle: {exc}") from None
    _log_keys(payload.get("log_keys", []))
    _admission(payload.get("admission_policies", {}))
    return payload


def _key_id(name: str, public: bytes) -> bytes:
    return hashlib.sha256(name.encode() + b"\n\x01" + public).digest()[:4]


def sign(payload: dict[str, Any], private: Any, name: str) -> bytes:
    """The signed note of a validated *payload*, signed by *private* as *name*."""
    if not name or any(c in name for c in " +\n"):
        raise BundleError("trust bundle: the owner name may not hold spaces, '+' or newlines")
    body = name.encode() + b"\n" + canonical_json(validate(payload)) + b"\n"
    public = private.public_key().public_bytes_raw()
    signature = base64.b64encode(_key_id(name, public) + private.sign(body)).decode()
    return body + f"\n{_DASH}{name} {signature}\n".encode()


def open_bundle(
    note: bytes, owner_vkey: str, now: datetime | None = None, min_serial: int = 0
) -> dict[str, Any]:
    """The payload of *note* if the pinned owner signed it and it is current."""
    from opentine._signing_keys import coerce_ed25519_public
    from opentine.repository._tlog import LogError
    from opentine.repository._tlog_note import parse_vkey

    try:
        name, public = parse_vkey(owner_vkey)
    except LogError as exc:
        raise BundleError(f"owner key: {exc}") from None
    if len(note) > MAX_BYTES:
        raise BundleError(f"trust bundle exceeds {MAX_BYTES} bytes")
    try:
        body, signatures = note.decode("utf-8").split("\n\n", 1)
        owner, text = body.split("\n")
        payload = json.loads(text, parse_int=_parse_int)
    except ValueError:
        raise BundleError("trust bundle is not a signed note over one JSON line") from None
    if owner != name:
        raise BundleError(f"trust bundle names owner {owner!r}, not the pinned {name!r}")
    if canonical_json(payload) != text.encode("utf-8"):
        raise BundleError("trust bundle payload is not canonical JSON")
    verifier = coerce_ed25519_public(public.hex())
    signed = False
    for line in signatures.splitlines():
        if not line.startswith(_DASH) or line[len(_DASH) :].split(" ")[0] != name:
            continue
        try:
            raw = base64.b64decode(line.rsplit(" ", 1)[1], validate=True)
            if raw[:4] == _key_id(name, public):
                verifier.verify(raw[4:], (body + "\n").encode())
                signed = True
        except Exception:  # noqa: BLE001 -- a bad signature line is just not a signature
            continue
    if not signed:
        raise BundleError("trust bundle is not signed by the pinned owner key")
    validate(payload)
    moment = now or datetime.now(UTC)
    if "expires_at" in payload and _time(payload["expires_at"], "expires_at") <= moment:
        raise BundleError("trust bundle has expired")
    if payload["serial"] < min_serial:
        raise BundleError(f"trust bundle serial {payload['serial']} is older than {min_serial}")
    return payload


def digest(note: bytes) -> str:
    return "sha256:" + hashlib.sha256(note).hexdigest()


__all__ = ["BundleError", "PORTABLE", "digest", "open_bundle", "sign", "validate"]
