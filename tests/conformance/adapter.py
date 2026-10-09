"""The 33 conformance ops, answered by the reference implementation.

This module, ``adapter_repo`` and ``adapter_write`` are the only place an
**answer** is produced. A third-party adapter replaces exactly these three files
and keeps everything else; ``docs/conformance/run_conformance.py``, the file a
third party actually executes, imports no ``opentine`` at all (a drift gate
enforces that).

``builders``, the ``cases_*`` modules and ``compat_index`` also import
``opentine`` -- to construct realistic *inputs*, and to read the golden fixture
set. That is deliberate: an input built by a second, hand-rolled encoder would
be testing that encoder. No expected output is ever produced outside an op call
here.

An op returns a JSON-shaped ``dict`` when the input is accepted and raises when
it is refused. The generator never transcribes a return value: whatever comes
back here becomes the vector's ``output``, and whatever is raised becomes its
``x_reference``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

from opentine._artifact_io import parse_artifact_json
from opentine._attest_view import ATTEST_SCHEMES, SIGNATURE_KEY
from opentine._attest_view import signed_message as attest_message
from opentine._canon import _canonical_bytes, _integrity_digest
from opentine._graph_serde import verify_integrity
from opentine._signing_verify import verify_block
from opentine._signing_view import SCHEMES as ARTIFACT_SCHEMES
from opentine._signing_view import signed_message as artifact_message
from opentine._unicode_text import assert_unicode_text, surrogate_suspect
from opentine.kernel import (
    ObjectEnvelope,
    canonical_json,
    object_id,
    parse_oid,
    validate_json_shape,
    validate_links,
)
from opentine.redaction import redact_blob, redact_value
from tests.conformance import adapter_repo as repo_ops
from tests.conformance import adapter_write as write_ops
from tests.conformance.keys import KEYS


@dataclass(frozen=True)
class OpInput:
    """One assembled op input: exactly one spelling is populated."""

    kind: str
    raw: bytes | None = None
    value: Any = None

    def bytes_(self) -> bytes:
        if self.raw is None:
            raise TypeError("this op consumes bytes; the case supplied a value")
        return self.raw


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# --------------------------------------------------------------------------- #
# Part 0 -- primitives
# --------------------------------------------------------------------------- #


def op_text_validate(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 0.1: refuse a document whose text holds an unpaired surrogate."""
    raw = inp.bytes_()
    import json as _json

    parsed = _json.loads(raw)
    if surrogate_suspect(raw):
        assert_unicode_text(parsed, where="conformance input")
    return {}


def op_canon_v3(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    return {"bytes_b64": _b64(canonical_json(inp.value))}


def op_canon_v2(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    return {"bytes_b64": _b64(_canonical_bytes(inp.value))}


def op_shape_scan(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    validate_json_shape(inp.bytes_(), max_tokens=int(args.get("max_tokens", 200_000)))
    return {}


# --------------------------------------------------------------------------- #
# Part 1 -- objects
# --------------------------------------------------------------------------- #


def op_envelope_decode(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    envelope = ObjectEnvelope.decode(inp.bytes_(), args.get("expected_oid"))
    return {
        "oid": envelope.oid,
        "type": envelope.object_type,
        "schema": envelope.schema,
        "encoding": envelope.encoding,
        "body_b64": _b64(envelope.body),
    }


def op_envelope_encode(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    header = args["header"]
    payload = inp.raw if inp.kind == "bytes" else inp.value
    envelope = ObjectEnvelope.create(header["type"], payload, int(header.get("schema", 1)))
    return {"bytes_b64": _b64(envelope.encode()), "oid": envelope.oid}


def op_oid_derive(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    header = args["header"]
    return {"oid": object_id(header["type"], header["schema"], inp.bytes_())}


def op_oid_parse(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    object_type, digest = parse_oid(inp.value)
    return {"type": object_type, "digest": digest}


def op_links_extract(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    envelope = ObjectEnvelope.decode(inp.bytes_())
    exists = repo_ops.existence(args)
    return {"links": sorted(validate_links(envelope, exists))}


def op_event_metrics(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    from opentine.repository._run_graph import validate_event_metrics

    validate_event_metrics(ObjectEnvelope.decode(inp.bytes_()))
    return {}


# --------------------------------------------------------------------------- #
# Part 3 -- the portable .tine artifact
# --------------------------------------------------------------------------- #


def op_artifact_parse(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    parsed = parse_artifact_json(inp.bytes_())
    keys = sorted(parsed) if isinstance(parsed, dict) else []
    return {"top_level_keys": keys}


def op_integrity_digest(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    return {"digest": _integrity_digest(parse_artifact_json(inp.bytes_()))}


def op_integrity_verify(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    result = verify_integrity(parse_artifact_json(inp.bytes_()))
    return {
        "ok": bool(result.ok),
        "algorithm": result.algorithm,
        "expected": result.expected,
        "actual": result.actual,
        "reason": result.reason,
    }


# --------------------------------------------------------------------------- #
# Part 4 -- signing
# --------------------------------------------------------------------------- #

_MESSAGE_BUILDERS = {
    "tine-sig/1": artifact_message,
    "tine-sig/2": artifact_message,
    "tine-attest/1": attest_message,
}


def op_sig_message(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    document = inp.value["document"]
    header = inp.value["header"]
    message = _MESSAGE_BUILDERS[args["scheme"]](document, header)
    out: dict[str, Any] = {"message_b64": _b64(message)}
    if args.get("key"):
        out["value"] = hmac.new(KEYS[args["key"]], message, hashlib.sha256).hexdigest()
    return out


def op_sig_verify(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    document = parse_artifact_json(inp.raw) if inp.kind == "bytes" else inp.value
    family = args.get("family", "attestation")
    if family == "attestation":
        block = document.get(SIGNATURE_KEY) if isinstance(document, dict) else None
        schemes = ATTEST_SCHEMES
        build = lambda header: attest_message(document, header)  # noqa: E731
    else:
        metadata = document.get("metadata") or {}
        block = (metadata.get("integrity") or {}).get("signature")
        schemes = ARTIFACT_SCHEMES
        build = lambda header: artifact_message(document, header)  # noqa: E731
    result = verify_block(
        block,
        build,
        schemes=schemes,
        subject=family,
        hmac_key=KEYS[args["key"]] if args.get("key") else None,
        public_key=bytes.fromhex(args["public_key"]) if args.get("public_key") else None,
        trust_embedded=bool(args.get("trust_embedded")),
    )
    return {
        "ok": result.ok,
        "state": result.state,
        "algorithm": result.algorithm,
        "key_id": result.key_id,
        "signer": result.signer,
        "signed_at": result.signed_at,
        "reason": result.reason,
    }


# --------------------------------------------------------------------------- #
# Part 1.4 -- redaction (writer-only, optional)
# --------------------------------------------------------------------------- #


def op_redact_blob(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    return {"bytes_b64": _b64(redact_blob(inp.bytes_()))}


def op_redact_value(inp: OpInput, args: dict[str, Any]) -> dict[str, Any]:
    from opentine._canon import _redact

    return {"bytes_b64": _b64(canonical_json(redact_value(_redact(inp.value))))}


OPS = {
    "text.validate": op_text_validate,
    "canon.v3": op_canon_v3,
    "canon.v2": op_canon_v2,
    "shape.scan": op_shape_scan,
    "envelope.decode": op_envelope_decode,
    "envelope.encode": op_envelope_encode,
    "oid.derive": op_oid_derive,
    "oid.parse": op_oid_parse,
    "links.extract": op_links_extract,
    "event.metrics": op_event_metrics,
    "artifact.parse": op_artifact_parse,
    "integrity.digest": op_integrity_digest,
    "integrity.verify": op_integrity_verify,
    "sig.message": op_sig_message,
    "sig.verify": op_sig_verify,
    "redact.blob": op_redact_blob,
    "redact.value": op_redact_value,
    **repo_ops.OPS,
    **write_ops.OPS,
}
