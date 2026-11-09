"""The conformance ops ``tine-verify.pyz`` answers with its own code (0.48 freeze audit).

Each op takes ``(raw bytes or None, decoded value or None, args)`` and returns
the output the vector pins, or raises (a refusal). Only the pyz's modules and
the ones vendored into it verbatim (``kernel``, ``_agent_identity``) are used,
so a test can run the suite through this table and show the pyz agrees with
the reference on every reader and verifier case of these families. The
families the pyz answers through its file verifiers (records, projects,
reviews, prompts, ...) are pinned by their own tests; ``tests/test_048_freeze``
holds the whole inventory.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from .. import _agent_identity as identity
from .. import kernel
from . import _delegation, _evalv, _fleet, _keyless, _sig, _tlog
from ._forgeclaim import forge_claim_verify


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _envelope(raw: Any, value: Any, args: dict) -> dict:
    envelope = kernel.ObjectEnvelope.decode(raw, args.get("expected_oid"))
    return {"oid": envelope.oid, "type": envelope.object_type, "schema": envelope.schema,
            "encoding": envelope.encoding, "body_b64": _b64(envelope.body)}  # fmt: skip


def _oid_parse(raw: Any, value: Any, args: dict) -> dict:
    object_type, digest = kernel.parse_oid(value)
    return {"type": object_type, "digest": digest}


def _agent_ref(raw: Any, value: Any, args: dict) -> dict:
    record = identity.validate(value)
    stable = {name: record[name] for name in identity.STABLE_FIELDS}
    hashed = identity.DOMAIN + kernel.canonical_json(stable)
    return {"ref": identity.agent_ref(record), "hashed_b64": _b64(hashed)}


def _actions_chain(raw: Any, value: Any, args: dict) -> dict:
    """SPEC 4.8: ``sha256(prev ':' digest)`` per entry, seeded from the run id."""
    link = hashlib.sha256(b"tine-actions/1\0" + value["run_id"].encode("utf-8")).hexdigest()
    links = []
    for digest in list(value["digests"]):
        link = hashlib.sha256(f"{link}:{digest}".encode()).hexdigest()
        links.append(link)
    return {"chain": links}


def _delegation_verify(raw: Any, value: Any, args: dict) -> dict:
    return _delegation.verify_chain(
        value["chain"], value["signer"], value["at"], value.get("agent"),
        list(value.get("actions") or ()), value.get("revoked"),
        value.get("time_verified", True),
    )  # fmt: skip


def _fleet_verify(raw: Any, value: Any, args: dict) -> dict:
    key = value.get("public_key")
    return _fleet.verify(value["document"], bytes.fromhex(key) if key else None)


def _eval_verdict(raw: Any, value: Any, args: dict) -> dict:
    key = value.get("public_key")
    found = _evalv.verify(value["verdict"], bytes.fromhex(key) if key else None)
    return {"item": found["item"], "passed": found["passed"], "signer": found["signer"]}


def _forge(raw: Any, value: Any, args: dict) -> dict:
    return forge_claim_verify(value["claim"], value["branch"], value["project"])


OPS = {
    "canon.v3": lambda raw, value, args: {"bytes_b64": _b64(kernel.canonical_json(value))},
    "canon.v2": lambda raw, value, args: {"bytes_b64": _b64(_sig.canon_v2(value))},
    "shape.scan": lambda raw, value, args: (
        kernel.validate_json_shape(raw, max_tokens=int(args.get("max_tokens", 200_000))) or {}
    ),
    "envelope.decode": _envelope,
    "oid.derive": lambda raw, value, args: {
        "oid": kernel.object_id(args["header"]["type"], args["header"]["schema"], raw)
    },
    "oid.parse": _oid_parse,
    "agent.ref": _agent_ref,
    "actions.chain": _actions_chain,
    "delegation.verify": _delegation_verify,
    "fleet.verify": _fleet_verify,
    "eval-verdict.verify": _eval_verdict,
    "keyless.signing-time": lambda raw, value, args: _keyless.signing_time(value),
    "tlog.inclusion": lambda raw, value, args: _tlog.inclusion(value),
    "tlog.consistency": lambda raw, value, args: _tlog.consistency_verdict(value),
    "tlog.quorum": lambda raw, value, args: _tlog.quorum(value),
    "forge-claim.verify": _forge,
}


def answer(op: str, raw: bytes | None, value: Any, args: dict) -> dict:
    """The pyz's answer to one case; ``KeyError`` for an op it does not answer here."""
    return OPS[op](raw, value, dict(args))


__all__ = ["OPS", "answer"]
