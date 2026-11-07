"""X15: ``TrustPolicyAdmission`` -- admit pushes by policy and emit a SLSA VSA.

A push lands as a ref update. Before it is admitted, ``check(identity,
operation, facts)`` decides it: it returns the verified levels (a list of
strings) to admit, or raises :class:`PermissionError` to refuse (403). Each
admitted ``update_ref`` then yields an in-toto Statement v1 whose predicate is a
SLSA Verification Summary Attestation (``verification_summary/v1``) naming the
pushed object, the policy and the verifier. With ``private_key`` the statement
is wrapped in a DSSE envelope (:func:`opentine.intoto.sign_statement`).

Statements go to ``sink(tenant, document)``; the most recent ``keep`` also stay on
``recent`` (a bounded deque) for inspection and tests.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine.remote.interfaces import AdmissionPolicy, Identity

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
VSA_TYPE = "https://slsa.dev/verification_summary/v1"
DEFAULT_VERIFIER = "https://opentine.dev/serve/trust-policy-admission"

Check = Callable[[Identity, str, dict[str, Any]], list[str]]


def admitted_levels(identity: Identity, operation: str, facts: dict[str, Any]) -> list[str]:
    """The default check: every earlier gate (auth, roles, quota) already passed."""
    return ["OPENTINE_ADMITTED"]


def build_vsa(
    tenant: str,
    ref: str,
    oid: str,
    levels: list[str],
    *,
    verifier: str = DEFAULT_VERIFIER,
    policy_uri: str = "opentine:admission/default",
    time_verified: str | None = None,
) -> dict[str, Any]:
    digest = oid.rsplit(":", 1)[-1]
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": oid, "digest": {"sha256": digest}}],
        "predicateType": VSA_TYPE,
        "predicate": {
            "verifier": {"id": verifier},
            "timeVerified": time_verified or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "resourceUri": f"tine://{tenant}/{ref}",
            "policy": {"uri": policy_uri},
            "inputAttestations": [],
            "verificationResult": "PASSED",
            "verifiedLevels": sorted({str(level) for level in levels}),
        },
    }


def directory_sink(root: str | Path) -> Callable[[str, dict[str, Any]], None]:
    """Write each statement to ``root/<tenant>/<sha256 of its JSON>.json``."""
    base = Path(root)

    def write(tenant: str, document: dict[str, Any]) -> None:
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        target = base / tenant
        target.mkdir(parents=True, exist_ok=True)
        (target / f"{hashlib.sha256(body).hexdigest()}.json").write_bytes(body)

    return write


class TrustPolicyAdmission:
    def __init__(
        self,
        check: Check = admitted_levels,
        *,
        sink: Callable[[str, dict[str, Any]], None] | None = None,
        private_key: Any = None,
        policy_uri: str = "opentine:admission/default",
        verifier: str = DEFAULT_VERIFIER,
        inner: AdmissionPolicy | None = None,
        keep: int = 256,
    ):
        self.check, self.sink, self.private_key = check, sink, private_key
        self.policy_uri, self.verifier, self.inner = policy_uri, verifier, inner
        self.recent: deque[dict[str, Any]] = deque(maxlen=max(1, keep))

    def admit(self, identity: Identity, operation: str, facts: dict[str, Any]) -> None:
        if self.inner is not None:
            self.inner.admit(identity, operation, facts)
        levels = self.check(identity, operation, facts)
        if not isinstance(levels, list):
            raise PermissionError("trust policy refused the push")
        if operation != "update_ref":
            return
        tenant = str(facts.get("tenant") or identity.tenant)
        statement = build_vsa(
            tenant,
            str(facts.get("name", "")),
            str(facts.get("new", "")),
            levels,
            verifier=self.verifier,
            policy_uri=self.policy_uri,
        )
        document: dict[str, Any] = statement
        if self.private_key is not None:
            from opentine.intoto import sign_statement

            document = sign_statement(statement, self.private_key)
        self.recent.append(document)
        if self.sink is not None:
            self.sink(tenant, document)
