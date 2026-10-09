"""The reference PROTOCOL.md adapter: opentine, answering the conformance suite.

This is the worked example to port. The loop is fifteen lines -- read a request
line, decode the tagged value tree, dispatch on ``op``, print one response line
-- and everything specific to opentine lives behind
``tests.conformance.adapter``. A third-party adapter replaces that import with
its own reader and keeps this file's shape.

``_CODES`` below is the one-time map Level 2 asks every implementer for: their
own error identifiers, mapped onto ``REASON_CODES.md``. opentine's messages are
deliberately coarser than the codes in places -- a lone surrogate and a depth
failure report the same string -- which is exactly what ``MANIFEST.alias_groups``
exists to absorb, so this map is allowed to land on a group rather than a code.

    python docs/conformance/run_conformance.py \\
        --adapter "python scripts/conformance_adapter.py" --level 2 \\
        --capability zlib --capability ed25519 --capability wtf8
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conformance import tagged  # noqa: E402
from tests.conformance.adapter import OPS, OpInput  # noqa: E402

#: op -> (message fragment, code), consulted before the shared table.
_OP_CODES: dict[str, tuple[tuple[str, str], ...]] = {
    "object.path": (("invalid typed object id", "path.invalid-oid"),),
    "artifact.parse": (
        ("unpaired UTF-16 surrogate", "artifact.lone-surrogate"),
        ("Expecting", "artifact.malformed-json"),
        ("Unterminated", "artifact.malformed-json"),
    ),
    "config.validate": (("JSON structure exceeds", "config.malformed"),),
}

#: message fragment -> code, longest fragment wins.
_CODES: tuple[tuple[str, str], ...] = (
    ("JSON structure exceeds", "shape.tokens-exceeded"),
    ("canonical JSON forbids NaN", "canon.non-finite"),
    ("canonical JSON integer exceeds", "canon.integer-overflow"),
    ("canonical JSON nesting exceeds", "canon.depth-exceeded"),
    ("canonical JSON nesting or Unicode key", "canon.unencodable-text"),
    ("unpaired UTF-16 surrogate", "text.lone-surrogate"),
    (".tine artifact nesting exceeds", "artifact.structure-excessive"),
    (".tine artifacts must use UTF-8 JSON", "artifact.nul-byte"),
    ("duplicate .tine object key", "artifact.duplicate-key"),
    ("non-finite number in .tine artifact", "artifact.non-finite"),
    ("integer in .tine artifact exceeds", "artifact.integer-too-many-digits"),
    ("malformed object envelope", "envelope.malformed"),
    ("non-canonical object header", "envelope.header-non-canonical"),
    ("non-canonical object body", "envelope.body-non-canonical"),
    ("malformed object JSON", "envelope.body-malformed-json"),
    ("invalid object schema", "envelope.schema-out-of-range"),
    ("unknown object type or encoding", "envelope.unknown-type"),
    ("object id mismatch", "envelope.oid-mismatch"),
    ("invalid typed object id", "oid.malformed"),
    ("parent_ids must contain event ids", "link.parent-ids-not-events"),
    ("causal_ids must contain event ids", "link.parent-ids-not-events"),
    ("_blob must contain a blob id", "link.event-blob-not-blob"),
    ("events must contain unique event ids", "link.run-events-invalid"),
    ("must contain unique events from the run", "link.run-roots-tips-invalid"),
    ("must be a subset of events", "link.run-roots-tips-not-subset"),
    ("manifests must be an object", "link.run-manifests-not-object"),
    ("run blob fields must contain blob ids", "link.run-blob-not-blob"),
    ("attestation target_id must contain a run id", "link.attestation-target-not-run"),
    ("previous_id must contain an annotation id", "link.annotation-previous-not-annotation"),
    ("missing linked object", "link.missing-object"),
    ("event usage must be a mapping", "metrics.usage-not-object"),
    ("must be a safe integer token count", "metrics.token-dimension-unsafe"),
    ("must be numeric", "metrics.usage-value-not-numeric"),
    ("must be finite and non-negative", "metrics.meter-not-finite"),
    ("run status is invalid", "graph.status-invalid"),
    ("parent outside its event graph", "graph.parent-outside-graph"),
    ("causal link outside its event graph", "graph.causal-outside-graph"),
    ("parent-before-child", "graph.order-not-topological"),
    ("run roots do not match", "graph.roots-mismatch"),
    ("run tips do not match", "graph.tips-mismatch"),
    ("legacy_refs must map", "graph.legacy-refs-invalid"),
    ("annotation previous object is unavailable", "chain.previous-unavailable"),
    ("annotation versions must target", "chain.target-changed"),
    ("repository config exceeds maximum size", "config.oversized"),
    ("repository config is malformed", "config.malformed"),
    ("repository config is incompatible", "config.incompatible"),
    ("annotation ref name must match", "ref.annotation-name-mismatch"),
    ("refs require", "ref.target-type"),
    ("invalid ref name", "ref.name-charset"),
    ("repository ref exceeds its size limit", "ref.file-oversized"),
    ("repository ref is not ASCII", "ref.file-not-ascii"),
    ("repository ref is not canonically encoded", "ref.file-not-canonical"),
    ("reflog actor exceeds", "reflog.actor-too-long"),
    ("reflog time_ns must be", "reflog.time-not-string"),
    ("shallow boundary state exceeds its byte limit", "shallow.oversized"),
    ("shallow boundary state exceeds its object limit", "shallow.too-many"),
    ("shallow boundary state must be ASCII", "shallow.not-ascii"),
    ("shallow boundary state has invalid line endings", "shallow.carriage-return"),
    ("shallow boundary state contains an empty", "shallow.empty-line"),
    ("shallow boundary state contains duplicate", "shallow.duplicate"),
    ("invalid pack header", "pack.bad-magic"),
    ("invalid compressed pack", "pack.invalid-compression"),
    ("truncated or trailing compressed", "pack.truncated-or-trailing"),
    ("pack checksum mismatch", "pack.checksum-mismatch"),
    ("invalid pack manifest", "pack.manifest-malformed"),
    ("non-canonical or unsupported pack", "pack.manifest-non-canonical"),
    ("invalid packed object", "pack.entry-shape"),
    ("pack contains duplicate object ids", "pack.duplicate-ids"),
    ("packed objects cannot also be shallow", "pack.shallow-overlaps-objects"),
    ("pack exceeds maximum object count", "pack.too-many-objects"),
    ("pack exceeds maximum transfer size", "pack.oversized"),
    ("pack has unresolved link", "pack.unresolved-link"),
    ("pack shallow boundaries do not match", "pack.shallow-not-link-closure"),
    ("payload must be an object", "sig.payload-not-object"),
    ("metadata must be an object", "sig.payload-not-object"),
)


def reason_for(operation: str, message: str) -> str:
    for fragment, code in _OP_CODES.get(operation, ()):
        if fragment in message:
            return code
    best = ""
    found = ""
    for fragment, code in _CODES:
        if fragment in message and len(fragment) > len(best):
            best, found = fragment, code
    return found


def op_input(spec: dict) -> OpInput:
    if "value" in spec:
        return OpInput("value", None, tagged.decode(spec["value"]))
    return OpInput("bytes", base64.b64decode(spec["bytes_b64"]), None)


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request = json.loads(line)
        response: dict = {"id": request["id"]}
        operation = OPS.get(request["op"])
        if operation is None:
            response["ok"] = False
            response["unsupported"] = True
        else:
            try:
                response["output"] = operation(
                    op_input(request["input"]), dict(request.get("args") or {})
                )
                response["ok"] = True
            except Exception as exc:  # noqa: BLE001 -- a refusal is the answer
                response["ok"] = False
                response["reason"] = reason_for(request["op"], str(exc))
                response["message"] = str(exc)[:200]
        sys.stdout.write(json.dumps(response, ensure_ascii=True) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
