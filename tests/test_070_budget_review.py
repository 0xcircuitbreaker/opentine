"""0.69 budget review: a loop pre-empting the owner's policy, and a gate whose policy is gone."""

from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _budget_gate, _budget_ledger, _budget_policy, _budget_status
from opentine._signing_pins import key_fingerprint
from opentine.attest_signing import sign_attestation
from opentine.repository._holds import BUDGET_LEDGER
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_070_budget_ledger import SUBJECT, T0, _apply, _key, _policy, repo  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _root_entry(repo, doc: dict, key: Ed25519PrivateKey, at_ms: int) -> str:  # noqa: F811
    """A forged ledger entry with no parent and an early clock, held like any other."""
    value = {"convention": _budget_ledger.CONVENTION, "subject": SUBJECT, "entry": "policy",
             "at": _budget_ledger.rfc3339(at_ms), "at_ms": at_ms, "policy": doc}  # fmt: skip
    payload = {"target_id": _budget_ledger.anchor(repo, SUBJECT), "value": value,
               "previous_id": None,
               "signer": key_fingerprint(key.public_key().public_bytes_raw())}  # fmt: skip
    payload["signature"] = sign_attestation(payload, key, algorithm="ed25519",
                                            signed_at=value["at"])  # fmt: skip
    oid = repo.put("annotation", payload, redact=False)
    _budget_ledger._hold(repo, oid, BUDGET_LEDGER + SUBJECT)
    return oid


def test_a_fresh_key_cannot_preempt_the_owner_policy_with_a_huge_serial(repo):  # noqa: F811
    owner = _apply(repo, _policy("policy", serial=5, tokens=25))
    fresh = Ed25519PrivateKey.from_private_bytes(bytes([99]) * 32)
    forged = _budget_policy.build(SUBJECT, {"tokens": 10**12}, serial=10**15,
                                  on_limit="deny", issued_at="2027-01-15T08:00:00Z")  # fmt: skip
    _root_entry(repo, _budget_policy.sign(forged, fresh), fresh, at_ms=0)
    body = _budget_status.status(repo, SUBJECT, now_ms=T0)
    assert body["policy"]["entry"] == owner
    assert body["policy"]["limits"]["tokens"] == 25


def test_the_gate_refuses_when_no_policy_is_in_force(repo, tmp_path):  # noqa: F811
    args = SimpleNamespace(repo=repo.path.parent.as_posix(), subject=SUBJECT,
                           key=(tmp_path / "runner.key").as_posix(), agent="generic")  # fmt: skip
    out = io.BytesIO()
    _budget_gate.run(args, io.BytesIO(b"{}"), out, now=lambda: T0)
    assert json.loads(out.getvalue())["decision"] == "deny"
    guard = _budget_gate.BudgetMcpGuard(repo, SUBJECT, _key("runner"), now=lambda: T0)
    call = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}\n'
    forward, back, _ = guard.check(call)
    assert forward is None and b"-32002" in back
