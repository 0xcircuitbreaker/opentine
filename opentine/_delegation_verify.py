"""Verify an ``opentine-delegation/1`` chain offline (X32).

:func:`verify_chain` walks the certificates root first and refuses, with a
``delegation.*`` code, the first thing wrong:

* ``delegation.malformed`` -- a certificate that is not well formed, or a chain
  that is empty or longer than ``MAX_CHAIN``;
* ``delegation.bad-signature`` -- a signature that does not verify under the
  embedded key, or an embedded key that is not the named ``issuer``;
* ``delegation.broken-chain`` -- a link whose ``issuer`` is not the previous
  ``subject`` or whose ``parent`` is not the previous certificate's digest (or a
  root with a ``parent``), or a root other than a pinned one;
* ``delegation.too-deep`` -- a link the parent's ``max_depth`` does not allow;
* ``delegation.scope-violation`` -- a child scope or window wider than its
  parent's, or a requested agent or action outside the leaf's scope;
* ``delegation.expired`` -- *at* outside a certificate's window;
* ``delegation.wrong-signer`` -- a leaf subject that is not the signing key.
"""

from __future__ import annotations

from typing import Any

from opentine import _signed_doc
from opentine._delegation import DOMAIN, MAX_CHAIN, DelegationError, body, digest
from opentine._key_lifecycle import parse_time
from opentine._signing_pins import key_fingerprint


def _fail(code: str, index: int, message: str) -> DelegationError:
    return DelegationError(f"delegation.{code}", f"certificate {index}: {message}")


def _signature(cert: dict[str, Any], checked: dict[str, Any], index: int) -> None:
    block = cert.get("signature")
    raw = block.get("public_key") if isinstance(block, dict) else None
    try:
        embedded = bytes.fromhex(raw) if isinstance(raw, str) else b""
    except ValueError:
        embedded = b""
    if len(embedded) != 32 or key_fingerprint(embedded) != checked["issuer"]:
        raise _fail("bad-signature", index, "the signing key is not the named issuer")
    verdict = _signed_doc.verify(DOMAIN, checked, block, public_key=embedded)
    if not verdict.ok:
        raise _fail("bad-signature", index, f"signature {verdict.state}: {verdict.reason}")


def _covers(parent: list[str], child: list[str]) -> bool:
    return "*" in parent or set(child) <= set(parent)


def _narrows(parent: dict[str, Any], child: dict[str, Any], index: int) -> None:
    if parent["scope"]["max_depth"] < 1:
        raise _fail("too-deep", index, "the parent certificate allows no further delegation")
    if child["scope"]["max_depth"] > parent["scope"]["max_depth"] - 1:
        raise _fail("too-deep", index, "max_depth must shrink by at least one per link")
    for name in ("agents", "actions"):
        if not _covers(parent["scope"][name], child["scope"][name]):
            raise _fail("scope-violation", index, f"{name} wider than the parent's")
    if parse_time(child["not_before"]) < parse_time(parent["not_before"]) or parse_time(
        child["not_after"]
    ) > parse_time(parent["not_after"]):
        raise _fail("scope-violation", index, "validity window wider than the parent's")


def verify_chain(
    chain: Any,
    *,
    signer: str,
    at: str,
    agent: str | None = None,
    actions: list[str] | tuple[str, ...] = (),
    root: str | None = None,
) -> dict[str, Any]:
    """The verified chain as ``{root, signer, links: [digest...], scope}``; raises else.

    *signer* is the fingerprint of the key that signed the work; *at* is the
    time the work was signed; *root*, when given, is the only trusted issuer.
    """
    if not isinstance(chain, list) or not chain or len(chain) > MAX_CHAIN:
        raise DelegationError("delegation.malformed", f"a chain holds 1..{MAX_CHAIN} certificates")
    when = parse_time(at, "signing time")
    checked: list[dict[str, Any]] = []
    for index, cert in enumerate(chain):
        current = body(cert)
        _signature(cert, current, index)
        if index == 0:
            if current["parent"]:
                raise _fail("broken-chain", 0, "the root certificate names a parent")
            if root is not None and current["issuer"] != root:
                raise _fail("broken-chain", 0, f"root issuer is not the trusted {root}")
        else:
            previous = checked[-1]
            if current["issuer"] != previous["subject"]:
                raise _fail("broken-chain", index, "issuer is not the previous subject")
            if current["parent"] != digest(chain[index - 1]):
                raise _fail("broken-chain", index, "parent is not the previous certificate")
            _narrows(previous, current, index)
        if not parse_time(current["not_before"]) <= when < parse_time(current["not_after"]):
            raise _fail("expired", index, f"{at} is outside {current['not_before']}..")
        checked.append(current)
    leaf = checked[-1]
    if leaf["subject"] != signer:
        raise _fail("wrong-signer", len(chain) - 1, f"subject is not the signer {signer}")
    if agent is not None and not _covers(leaf["scope"]["agents"], [agent]):
        raise _fail("scope-violation", len(chain) - 1, f"agent {agent!r} is not delegated")
    outside = [a for a in actions if not _covers(leaf["scope"]["actions"], [a])]
    if outside:
        raise _fail("scope-violation", len(chain) - 1, f"actions not delegated: {outside}")
    return {
        "root": checked[0]["issuer"],
        "signer": signer,
        "links": [digest(cert) for cert in chain],
        "scope": leaf["scope"],
    }


__all__ = ["verify_chain"]
