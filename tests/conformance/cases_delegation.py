"""SPEC 4.10 ``opentine-delegation/1``: verifying a delegation chain offline (X32).

The chains are built here with the published seeds in ``keys`` (Ed25519 is
deterministic, and every certificate fixes its ``signed_at``), so the input
bytes are stable. Only the op in ``adapter_delegation`` produces an answer.
"""

from __future__ import annotations

import copy

from opentine._delegation import issue
from opentine._signing_pins import key_fingerprint
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.keys import KEYS

VERIFIER = "verifier"
START, END, AT = "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", "2026-06-01T00:00:00Z"
SIGNED_AT = "2026-01-01T00:00:00Z"


def _public(name: str) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(KEYS[name]).public_key().public_bytes_raw()


ROOT, MID, LEAF = "ed25519_seed", "ed25519_seed_b", "ed25519_seed_c"
LEAF_FPR = key_fingerprint(_public(LEAF))
MID_FPR = key_fingerprint(_public(MID))
ROOT_FPR = key_fingerprint(_public(ROOT))
BEFORE, AFTER = "2026-03-01T00:00:00Z", "2026-09-01T00:00:00Z"


def _cert(issuer: str, subject: str, parent=None, **scope) -> dict:
    fields = {"agents": ["*"], "actions": ["*"], "max_depth": 0, "not_before": START,
              "not_after": END, **scope}  # fmt: skip
    return issue(KEYS[issuer], _public(subject), parent=parent, signed_at=SIGNED_AT, **fields)


FIRST = _cert(ROOT, MID, max_depth=1)
SECOND = _cert(MID, LEAF, FIRST, agents=["coder"], actions=["Bash", "Read"])
CHAIN = [FIRST, SECOND]


def _tampered() -> list:
    chain = copy.deepcopy(CHAIN)
    chain[1]["scope"]["actions"] = ["*"]
    return chain


def _case(
    name: str, expect: str, intent: str, chain, reason=None, family="delegation", **request
) -> Case:
    value = {"chain": chain, "signer": LEAF_FPR, "at": AT, "agent": "coder",
             "actions": ["Bash"], **request}  # fmt: skip
    return Case(
        id=f"{family}.{name}",
        section="4.10" if family == "delegation" else "4.10.1",
        checklist=(8,),
        op="delegation.verify",
        profile=VERIFIER,
        expect=expect,
        intent=intent,
        input=V(value),
        reason=reason,
    )


DELEGATION = Family(
    "56-delegation.json",
    "4.10",
    "delegation",
    (
        _case("valid", ACCEPT, "a two-link chain verifies for its leaf key, agent and tool", CHAIN),
        _case(
            "expired",
            REJECT,
            "a signing time after not_after is refused",
            CHAIN,
            "delegation.expired",
            at="2027-06-01T00:00:00Z",
        ),
        _case(
            "scope-violation",
            REJECT,
            "a tool outside the leaf's actions is refused",
            CHAIN,
            "delegation.scope-violation",
            actions=["Write"],
        ),
        _case(
            "broken-chain",
            REJECT,
            "a leaf certificate without the root it names as parent is refused",
            [SECOND],
            "delegation.broken-chain",
        ),
        _case(
            "wrong-signer",
            REJECT,
            "work signed by a key other than the leaf subject is refused",
            CHAIN,
            "delegation.wrong-signer",
            signer=MID_FPR,
        ),
        _case(
            "widened-scope",
            REJECT,
            "a certificate edited after signing fails its signature",
            _tampered(),
            "delegation.bad-signature",
        ),
        _case(
            "too-deep",
            REJECT,
            "a link under a certificate with max_depth 0 is refused",
            [_cert(ROOT, MID), _cert(MID, LEAF, _cert(ROOT, MID))],
            "delegation.too-deep",
        ),
    ),
)


def _revoked(name: str, expect: str, intent: str, revoked: dict, **request) -> Case:
    reason = "delegation.revoked" if expect == REJECT else None
    return _case(name, expect, intent, CHAIN, reason, "delegation-revocation",
                 revoked=revoked, **request)  # fmt: skip


#: 0.48: delegation x revocation registry semantics (SPEC 4.10.1).
REVOCATION = Family(
    "76-delegation-revocation.json",
    "4.10.1",
    "delegation-revocation",
    (
        _revoked(
            "leaf-revoked-before",
            REJECT,
            "the leaf key revoked before the verified signing time refuses the chain",
            {LEAF_FPR: BEFORE},
        ),  # fmt: skip
        _revoked(
            "leaf-revoked-after",
            ACCEPT,
            "the leaf key revoked after the verified signing time still verifies",
            {LEAF_FPR: AFTER},
        ),  # fmt: skip
        _revoked(
            "root-revoked-before",
            REJECT,
            "a revoked root issuer refuses the whole chain",
            {ROOT_FPR: BEFORE},
        ),  # fmt: skip
        _revoked(
            "mid-revoked-before",
            REJECT,
            "a revoked intermediate key refuses the chain",
            {MID_FPR: BEFORE},
        ),  # fmt: skip
        _revoked(
            "revoked-at-signing",
            REJECT,
            "revoked_at equal to the signing time refuses",
            {LEAF_FPR: AT},
        ),  # fmt: skip
        _revoked(
            "unverified-time",
            REJECT,
            "any revocation on the chain refuses when the signing time is only claimed",
            {MID_FPR: AFTER},
            time_verified=False,
        ),  # fmt: skip
        _revoked(
            "unverified-unrelated",
            ACCEPT,
            "a revocation of a key off the chain does not matter, verified time or not",
            {"sha256:" + "0" * 64: BEFORE},
            time_verified=False,
        ),  # fmt: skip
    ),
)

FAMILIES = (DELEGATION, REVOCATION)
