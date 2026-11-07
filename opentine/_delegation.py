"""``opentine-delegation/1``: a principal key hands scoped authority to an agent key (X32).

Before 0.43 a fleet member's identity was self-asserted (``_agent_identity``).
A delegation certificate is the missing link: the *issuer* key signs, with a
``tine-sig/3`` block over its own domain (``_signed_doc``), that the *subject*
key may act for it within a scope and a time window::

    {"scheme": "opentine-delegation/1",
     "issuer": "sha256:<fpr>", "subject": "sha256:<fpr>",
     "scope": {"agents": [...], "actions": [...], "max_depth": N},
     "not_before": RFC 3339, "not_after": RFC 3339,
     "parent": "" | "sha256:<digest of the certificate above it>",
     "signature": {tine-sig/3 block, Ed25519, embedded issuer key}}

``agents`` and ``actions`` are non-empty lists of names (``"*"`` is any);
``max_depth`` is how many further delegations the subject may issue. A chain
is a list of certificates, root first (``_delegation_verify``). Everything
needed to verify is in the certificates, so verification is fully offline.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from opentine import _signed_doc
from opentine._key_lifecycle import parse_time, stamp
from opentine._signing_pins import key_fingerprint
from opentine.kernel import KernelError, canonical_json

SCHEME = "opentine-delegation/1"
DOMAIN = b"opentine.delegation.v1:"
FPR_RE = re.compile(r"sha256:[0-9a-f]{64}")
NAME_RE = re.compile(r"[A-Za-z0-9_.:*/-]{1,128}")
FIELDS = ("scheme", "issuer", "subject", "scope", "not_before", "not_after", "parent")
SCOPE_FIELDS = ("agents", "actions", "max_depth")
#: Certificates one chain may hold; a deeper chain is refused outright.
MAX_CHAIN = 8
MAX_NAMES = 64


class DelegationError(ValueError):
    """A refusal; ``code`` is the conformance reason (``delegation.*``)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _malformed(message: str) -> DelegationError:
    return DelegationError("delegation.malformed", message)


def _names(value: Any, what: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_NAMES:
        raise _malformed(f"scope.{what} must be a non-empty list of names")
    if not all(isinstance(v, str) and NAME_RE.fullmatch(v) for v in value):
        raise _malformed(f"scope.{what} holds a malformed name")
    return sorted(set(value))


def check_scope(scope: Any) -> dict[str, Any]:
    if not isinstance(scope, dict) or set(scope) != set(SCOPE_FIELDS):
        raise _malformed("scope must have exactly agents, actions and max_depth")
    depth = scope["max_depth"]
    if type(depth) is not int or not 0 <= depth < MAX_CHAIN:
        raise _malformed(f"scope.max_depth must be an integer 0..{MAX_CHAIN - 1}")
    return {
        "agents": _names(scope["agents"], "agents"),
        "actions": _names(scope["actions"], "actions"),
        "max_depth": depth,
    }


def body(cert: Any) -> dict[str, Any]:
    """The signed part of *cert*, checked field by field."""
    if not isinstance(cert, dict) or cert.get("scheme") != SCHEME:
        raise _malformed("not an opentine-delegation/1 certificate")
    if set(cert) - {*FIELDS, "signature"}:
        raise _malformed("unknown field in delegation certificate")
    out = {name: cert.get(name) for name in FIELDS}
    for name in ("issuer", "subject"):
        if not isinstance(out[name], str) or not FPR_RE.fullmatch(out[name]):
            raise _malformed(f"{name} must be sha256: + 64 lower hex")
    if out["parent"] != "" and not (
        isinstance(out["parent"], str) and FPR_RE.fullmatch(out["parent"])
    ):
        raise _malformed("parent must be empty or sha256: + 64 lower hex")
    if out["scope"] != check_scope(out["scope"]):
        raise _malformed("scope lists must be sorted and free of duplicates")
    start = parse_time(out["not_before"], "not_before")
    end = parse_time(out["not_after"], "not_after")
    if end <= start:
        raise _malformed("not_after must be later than not_before")
    return out


def digest(cert: dict[str, Any]) -> str:
    """``sha256:`` over the domain and JCS of the whole certificate, signature included."""
    try:
        return "sha256:" + hashlib.sha256(DOMAIN + canonical_json(cert)).hexdigest()
    except KernelError as exc:
        raise _malformed(f"certificate cannot be canonicalized: {exc}") from exc


def issue(
    issuer_key: Any,
    subject_public: bytes,
    *,
    agents: list[str],
    actions: list[str],
    max_depth: int = 0,
    not_before: str,
    not_after: str,
    parent: dict[str, Any] | None = None,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """A signed certificate; *parent* is the certificate the issuer holds, if any."""
    from opentine._signing_keys import load_ed25519_private

    private = load_ed25519_private(issuer_key)
    issuer_raw = private.public_key().public_bytes_raw()
    cert = {
        "scheme": SCHEME,
        "issuer": key_fingerprint(issuer_raw),
        "subject": key_fingerprint(bytes(subject_public)),
        "scope": check_scope({"agents": agents, "actions": actions, "max_depth": max_depth}),
        "not_before": stamp(parse_time(not_before, "not_before")),
        "not_after": stamp(parse_time(not_after, "not_after")),
        "parent": digest(parent) if parent is not None else "",
    }
    checked = body(cert)
    cert["signature"] = _signed_doc.sign(
        DOMAIN, checked, private, signer=cert["issuer"], signed_at=signed_at
    )
    return cert


def summary(cert: dict[str, Any]) -> dict[str, Any]:
    """The fields a human or ``--json`` reader sees, plus the certificate digest."""
    out = {name: cert.get(name) for name in FIELDS if name != "scheme"}
    return {"digest": digest(cert), **out}


__all__ = [
    "DOMAIN",
    "MAX_CHAIN",
    "SCHEME",
    "DelegationError",
    "body",
    "check_scope",
    "digest",
    "issue",
    "summary",
]
