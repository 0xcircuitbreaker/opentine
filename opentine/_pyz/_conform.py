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
import hmac
from typing import Any

from .. import _agent_identity as identity
from .. import kernel
from . import (
    _conform_artifact,
    _conform_docs,
    _conform_records,
    _conform_sig,
    _conform_store,
    _delegation,
    _evalv,
    _fleet,
    _keyless,
    _sig,
    _tlog,
)
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
    **_conform_records.OPS,
    **_conform_artifact.OPS,
    **_conform_store.OPS,
    **_conform_docs.OPS,
}


def _key_args(args: dict, keys: dict[str, bytes]) -> dict:
    """The verification keys a case names (``docs/conformance/keys.json`` by name)."""
    public = args.get("public_key")
    return {
        "hmac_key": keys[args["key"]] if args.get("key") else None,
        "public_key": bytes.fromhex(public) if public else None,
        "trust_embedded": bool(args.get("trust_embedded")),
    }


def _sig_message(raw: Any, value: Any, args: dict, keys: dict) -> dict:
    message = _conform_sig.MESSAGES[args["scheme"]](value["document"], value["header"])
    out = {"message_b64": _b64(message)}
    if args.get("key"):
        out["value"] = hmac.new(keys[args["key"]], message, hashlib.sha256).hexdigest()
    return out


def _sig_verify(raw: Any, value: Any, args: dict, keys: dict) -> dict:
    document = _conform_artifact.parse(raw) if raw is not None else value
    family, found = args.get("family", "attestation"), _key_args(args, keys)
    if family in ("artifact-v4", "artifact-v5"):
        return _conform_sig.verify_v4(document, found)
    if family == "attestation":
        block = document.get("signature") if isinstance(document, dict) else None
        schemes: tuple[str, ...] = ("tine-attest/1", "tine-attest/2")
        build = _conform_sig.attest_message
    else:
        metadata = document.get("metadata") or {}
        block = (metadata.get("integrity") or {}).get("signature")
        schemes, build = ("tine-sig/1", "tine-sig/2"), _conform_sig.artifact_message
    return _conform_sig.verify_block(
        block, lambda header: build(document, header), schemes, family, found
    )


#: Ops that take the published test keys as well.
KEYED = {"sig.message": _sig_message, "sig.verify": _sig_verify}


def answer(
    op: str, raw: bytes | None, value: Any, args: dict, keys: dict[str, bytes] | None = None
) -> dict:
    """The pyz's answer to one case; ``KeyError`` for an op it does not answer here.

    *keys* maps the names of ``docs/conformance/keys.json`` to key bytes, for
    the ``sig.*`` ops a case names a key in.
    """
    if op in KEYED:
        return KEYED[op](raw, value, dict(args), dict(keys or {}))
    return OPS[op](raw, value, dict(args))


__all__ = ["KEYED", "OPS", "answer"]
