"""``opentine-delegation/1`` chains for ``tine-verify.pyz`` (SPEC 4.10, 4.10.1).

An independent stdlib port of ``opentine._delegation.body``/``digest`` and
``opentine._delegation_verify.verify_chain``, including the 0.48 revocation
rule: a key on the chain revoked at or before the verified signing time (or
revoked at all when the time is only claimed) refuses the chain. Every
refusal is a :class:`Refused` carrying the same ``delegation.*`` code.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from .. import kernel
from . import _sig
from ._gitobj import Refused

SCHEME = "opentine-delegation/1"
DOMAIN = b"opentine.delegation.v1:"
FPR = re.compile(r"sha256:[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9_.:*/-]{1,128}")
FIELDS = ("scheme", "issuer", "subject", "scope", "not_before", "not_after", "parent")
MAX_CHAIN = 8
MAX_NAMES = 64


def _no(code: str, message: str) -> Refused:
    return Refused(f"delegation.{code}", message)


def parse_time(value: Any, what: str = "time") -> datetime:
    if not isinstance(value, str):
        raise _no("malformed", f"{what} must be an RFC 3339 time")
    try:
        when = datetime.fromisoformat(value)
    except ValueError:
        raise _no("malformed", f"{what} {value!r} is not an RFC 3339 time") from None
    if when.tzinfo is None:
        raise _no("malformed", f"{what} {value!r} has no time zone")
    return when.astimezone(UTC)


def _names(value: Any, what: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_NAMES:
        raise _no("malformed", f"scope.{what} must be a non-empty list of names")
    if not all(isinstance(v, str) and NAME.fullmatch(v) for v in value):
        raise _no("malformed", f"scope.{what} holds a malformed name")
    return sorted(set(value))


def body(cert: Any) -> dict[str, Any]:
    if not isinstance(cert, dict) or cert.get("scheme") != SCHEME:
        raise _no("malformed", "not an opentine-delegation/1 certificate")
    if set(cert) - {*FIELDS, "signature"}:
        raise _no("malformed", "unknown field in delegation certificate")
    out = {name: cert.get(name) for name in FIELDS}
    for name in ("issuer", "subject"):
        if not isinstance(out[name], str) or not FPR.fullmatch(out[name]):
            raise _no("malformed", f"{name} must be sha256: + 64 lower hex")
    parent = out["parent"]
    if parent != "" and not (isinstance(parent, str) and FPR.fullmatch(parent)):
        raise _no("malformed", "parent must be empty or sha256: + 64 lower hex")
    scope = out["scope"]
    if not isinstance(scope, dict) or set(scope) != {"agents", "actions", "max_depth"}:
        raise _no("malformed", "scope must have exactly agents, actions and max_depth")
    depth = scope["max_depth"]
    if type(depth) is not int or not 0 <= depth < MAX_CHAIN:
        raise _no("malformed", f"scope.max_depth must be an integer 0..{MAX_CHAIN - 1}")
    for name in ("agents", "actions"):
        if scope[name] != _names(scope[name], name):
            raise _no("malformed", "scope lists must be sorted and free of duplicates")
    if parse_time(out["not_after"], "not_after") <= parse_time(out["not_before"], "not_before"):
        raise _no("malformed", "not_after must be later than not_before")
    return out


def digest(cert: Any) -> str:
    try:
        return "sha256:" + hashlib.sha256(DOMAIN + kernel.canonical_json(cert)).hexdigest()
    except kernel.KernelError as exc:
        raise _no("malformed", f"certificate cannot be canonicalized: {exc}") from None


def _signature(cert: dict, checked: dict, index: int) -> None:
    block = cert.get("signature")
    raw = block.get("public_key") if isinstance(block, dict) else None
    embedded = bytes.fromhex(raw) if _sig.lower_hex(raw, 64) else b""
    if len(embedded) != 32 or "sha256:" + hashlib.sha256(embedded).hexdigest() != checked["issuer"]:
        raise _no("bad-signature", f"certificate {index}: the signing key is not the named issuer")
    if block.get("alg") != "ed25519":
        raise _no("bad-signature", f"certificate {index}: Ed25519 only")

    def message(header: dict[str, Any]) -> bytes:
        return DOMAIN + kernel.canonical_json({"body": checked, "header": header})

    ok, state, reason = _sig.verify_block(
        block, message, ("tine-sig/3",), hmac_key=None, public_key=embedded
    )
    if not ok:
        raise _no("bad-signature", f"certificate {index}: signature {state}: {reason}")


def _covers(parent: list, child: list) -> bool:
    return "*" in parent or set(child) <= set(parent)


def _narrows(parent: dict, child: dict, index: int) -> None:
    if parent["scope"]["max_depth"] < 1:
        raise _no("too-deep", f"certificate {index}: the parent allows no further delegation")
    if child["scope"]["max_depth"] > parent["scope"]["max_depth"] - 1:
        raise _no("too-deep", f"certificate {index}: max_depth must shrink by at least one")
    for name in ("agents", "actions"):
        if not _covers(parent["scope"][name], child["scope"][name]):
            raise _no("scope-violation", f"certificate {index}: {name} wider than the parent's")
    if parse_time(child["not_before"]) < parse_time(parent["not_before"]) or parse_time(
        child["not_after"]
    ) > parse_time(parent["not_after"]):
        raise _no(
            "scope-violation", f"certificate {index}: validity window wider than the parent's"
        )


def _revocation(checked: list, revoked: Any, when: datetime, verified: bool) -> None:
    table = revoked if isinstance(revoked, dict) else {}
    for index, cert in enumerate(checked):
        keys = [cert["issuer"]] + ([cert["subject"]] if index == len(checked) - 1 else [])
        for key in keys:
            at = table.get(key)
            if at is None:
                continue
            if not verified or parse_time(at, "revoked_at") <= when:
                raise _no("revoked", f"certificate {index}: key {key} revoked at {at}")


def verify_chain(
    chain: Any,
    signer: Any,
    at: Any,
    agent: Any = None,
    actions: Any = (),
    revoked: Any = None,
    time_verified: bool = True,
) -> dict[str, Any]:
    """``{root, links}`` of a chain that holds for *signer* at *at*; raises :class:`Refused`."""
    if not isinstance(chain, list) or not chain or len(chain) > MAX_CHAIN:
        raise _no("malformed", f"a chain holds 1..{MAX_CHAIN} certificates")
    when = parse_time(at, "signing time")
    checked: list[dict] = []
    for index, cert in enumerate(chain):
        current = body(cert)
        _signature(cert, current, index)
        if index == 0 and current["parent"]:
            raise _no("broken-chain", "certificate 0: the root certificate names a parent")
        if index:
            if current["issuer"] != checked[-1]["subject"]:
                raise _no(
                    "broken-chain", f"certificate {index}: issuer is not the previous subject"
                )
            if current["parent"] != digest(chain[index - 1]):
                raise _no("broken-chain", f"certificate {index}: parent is not the previous one")
            _narrows(checked[-1], current, index)
        if not parse_time(current["not_before"]) <= when < parse_time(current["not_after"]):
            raise _no("expired", f"certificate {index}: {at} is outside its window")
        checked.append(current)
    _revocation(checked, revoked, when, time_verified)
    leaf, last = checked[-1], len(chain) - 1
    if leaf["subject"] != signer:
        raise _no("wrong-signer", f"certificate {last}: subject is not the signer {signer}")
    names = [agent] if isinstance(agent, str) else list(agent or [])
    if agent is not None and not any(_covers(leaf["scope"]["agents"], [n]) for n in names):
        raise _no("scope-violation", f"certificate {last}: agent {agent!r} is not delegated")
    outside = [a for a in actions or () if not _covers(leaf["scope"]["actions"], [a])]
    if outside:
        raise _no("scope-violation", f"certificate {last}: actions not delegated: {outside}")
    return {"root": checked[0]["issuer"], "links": [digest(cert) for cert in chain]}


__all__ = ["Refused", "body", "digest", "parse_time", "verify_chain"]
