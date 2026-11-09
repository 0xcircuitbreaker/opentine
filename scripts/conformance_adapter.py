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
        --capability zlib --capability ed25519 --capability ml-dsa-65 --capability wtf8
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
    "agent.ref": (
        ("unknown field in agent identity", "agent.unknown-field"),
        ("agent identity needs a harness", "agent.harness-missing"),
        ("is not normalised", "agent.not-normalised"),
        ("is malformed", "agent.field-malformed"),
    ),
    "delegation.verify": (
        ("is outside", "delegation.expired"),
        ("is not delegated", "delegation.scope-violation"),
        ("not delegated:", "delegation.scope-violation"),
        ("wider than the parent", "delegation.scope-violation"),
        ("is not the signer", "delegation.wrong-signer"),
        ("signing key is not the named issuer", "delegation.bad-signature"),
        ("signature ", "delegation.bad-signature"),
        ("no further delegation", "delegation.too-deep"),
        ("max_depth must shrink", "delegation.too-deep"),
        ("names a parent", "delegation.broken-chain"),
        ("is not the previous", "delegation.broken-chain"),
        ("root issuer is not", "delegation.broken-chain"),
    ),
    "eval-verdict.verify": (
        ("signing key is not the signer", "eval-verdict.bad-signature"),
        ("signature ", "eval-verdict.bad-signature"),
        ("other than the trusted one", "eval-verdict.wrong-key"),
        ("passed disagrees", "eval-verdict.inconsistent"),
        ("names a judge_run", "eval-verdict.judge-mismatch"),
        ("tine-eval-verdict/1", "eval-verdict.malformed"),
        ("must be", "eval-verdict.malformed"),
    ),
    "redaction-report.verify": (
        ("report is malformed", "redaction-report.malformed"),
        ("report is unsigned", "redaction-report.unsigned"),
        ("no key for", "redaction-report.no-key"),
        ("report signature", "redaction-report.bad-signature"),
        ("trusted key", "redaction-report.wrong-key"),
        ("clean disagrees", "redaction-report.inconsistent"),
    ),
    "tombstone.verify": (
        ("tombstone is malformed", "tombstone.malformed"),
        ("tombstone is unsigned", "tombstone.unsigned"),
        ("no key for", "tombstone.no-key"),
        ("tombstone signature", "tombstone.bad-signature"),
        ("trusted key", "tombstone.wrong-key"),
    ),
    "tombstone.closure": (
        ("tombstone is malformed", "tombstone.malformed"),
        ("no tombstone names it", "tombstone.missing-content"),
        ("exceeds its object cap", "tombstone.missing-content"),
    ),
    "redacted-copy.verify": (
        ("copy is malformed", "redacted-copy.malformed"),
        ("copy is unsigned", "redacted-copy.unsigned"),
        ("no key for", "redacted-copy.no-key"),
        ("copy signature", "redacted-copy.bad-signature"),
        ("trusted key", "redacted-copy.wrong-key"),
        ("names another pack", "redacted-copy.pack-mismatch"),
        ("redacted exceeds objects", "redacted-copy.inconsistent"),
        ("run oids must be equal", "redacted-copy.inconsistent"),
    ),
    "project.verify": (
        ("breaks the project chain", "project.chain-break"),
        ("project manifest is malformed", "project.malformed"),
        ("private upstream", "project.private-upstream"),
        ("plaintext locator", "project.plaintext-locator"),
        ("manifest is unsigned", "project.unsigned"),
        ("manifest signature", "project.bad-signature"),
        ("Ed25519 key", "project.wrong-signer"),
        ("not signed by", "project.wrong-signer"),
    ),
    "mirror-state.verify": (
        ("mirror state is malformed", "mirror-state.malformed"),
        ("mirror state is unsigned", "mirror-state.unsigned"),
        ("mirror state signature", "mirror-state.bad-signature"),
        ("signed by a project owner", "mirror-state.user-signed"),
        ("host key", "mirror-state.wrong-key"),
        ("trusted key", "mirror-state.wrong-key"),
        ("unknown mirror reason", "mirror-state.unknown-reason"),
        ("do not explain status", "mirror-state.inconsistent"),
    ),
    "prompt.verify": (
        ("prompt version is malformed", "prompt.malformed"),
        ("prompt version is unsigned", "prompt.unsigned"),
        ("prompt version signature", "prompt.bad-signature"),
        ("signed with an Ed25519 key", "prompt.wrong-key"),
        ("trusted key", "prompt.wrong-key"),
        ("predecessor's key", "prompt.wrong-signer"),
        ("does not follow its predecessor", "prompt.chain-break"),
        ("placeholders", "prompt.variables-mismatch"),
    ),
    "memory.verify": (
        ("memory note is malformed", "memory.malformed"),
        ("memory note is unsigned", "memory.unsigned"),
        ("memory note signature", "memory.bad-signature"),
        ("signed with an Ed25519 key", "memory.wrong-key"),
        ("trusted key", "memory.wrong-key"),
        ("not on the team", "memory.untrusted-signer"),
    ),
    "git-object.check": (
        ("git object is malformed", "git-object.malformed"),
        ("do not hash to", "git-object.mismatch"),
    ),
    "merge.compute": (
        ("cannot merge a run with itself", "merge.same-run"),
        ("up to date", "merge.up-to-date"),
        ("merge input is malformed", "merge.malformed"),
    ),
    "merge.pick": (("pick", "merge.malformed"),),
    "merge.verify": (
        ("merge record is malformed", "merge.malformed"),
        ("merge record is unsigned", "merge.unsigned"),
        ("no key for", "merge.no-key"),
        ("merge record signature", "merge.bad-signature"),
        ("trusted key", "merge.wrong-key"),
        ("names another run", "merge.run-mismatch"),
        ("other parents", "merge.run-mismatch"),
    ),
    "merge-approval.verify": (
        ("merge-approval record is malformed", "merge-approval.malformed"),
        ("merge-approval record is unsigned", "merge-approval.unsigned"),
        ("merge-approval record signature", "merge-approval.bad-signature"),
        ("no key for", "merge-approval.no-key"),
        ("trusted key", "merge-approval.wrong-key"),
    ),
    "review-finding.verify": (
        ("review finding is malformed", "review-finding.malformed"),
        ("review finding is unsigned", "review-finding.unsigned"),
        ("review finding signature", "review-finding.bad-signature"),
        ("signed with an Ed25519 key", "review-finding.wrong-key"),
        ("trusted key", "review-finding.wrong-key"),
        ("not a reviewer", "review-finding.untrusted-signer"),
    ),
    "oms.verify": (
        ("OMS bundle is malformed", "oms.malformed"),
        ("OMS payload is malformed", "oms.malformed"),
        ("payloadType is not", "oms.unsupported"),
        ("keyless OMS bundles", "oms.unsupported"),
        ("predicateType is not", "oms.unsupported"),
        ("serialization is not", "oms.unsupported"),
        ("hash_type is not", "oms.unsupported"),
        ("no public key given", "oms.no-key"),
        ("signature does not verify", "oms.bad-signature"),
        ("subject digest is not", "oms.root-mismatch"),
        ("model file is missing", "oms.missing-file"),
        ("does not match its signed digest", "oms.digest-mismatch"),
        ("not covered by the signature", "oms.extra-file"),
    ),
    "forge-claim.verify": (
        ("no forge claim", "forge-claim.missing"),
        ("forge claim is malformed", "forge-claim.malformed"),
        ("not the default branch", "forge-claim.not-default-branch"),
        ("names another project or tenant", "forge-claim.wrong-project"),
        ("fingerprint names another project", "forge-claim.wrong-fingerprint"),
    ),
    "forge-check.verify": (
        ("forge check is malformed", "forge-check.malformed"),
        ("share does not match", "forge-check.share-mismatch"),
        ("conclusion does not follow", "forge-check.conclusion-mismatch"),
        ("bundle does not hash", "forge-check.bundle-mismatch"),
    ),
}
_OP_CODES["project.chain"] = _OP_CODES["project.verify"]
#: 0.47 Reviews: the gate fragments first, so a decision's refusal is never read as a version's.
_OP_CODES["review.bundle"] = (
    ("review gate decision is malformed", "review-gate.malformed"),
    ("review gate decision is unsigned", "review-gate.unsigned"),
    ("review gate decision signature", "review-gate.bad-signature"),
    ("review gate decision is signed with", "review-gate.wrong-signer"),
    ("decision is not signed by", "review-gate.wrong-signer"),
    ("names another review version", "review-gate.wrong-review"),
    ("decision names no", "review-gate.wrong-review"),
    ("is not a gate of it", "review-gate.unknown-gate"),
    ("approval is blocked", "review-gate.blocked"),
    ("review is malformed", "review.malformed"),
    ("review is unsigned", "review.unsigned"),
    ("review signature", "review.bad-signature"),
    ("review is signed with", "review.wrong-signer"),
    ("not signed by", "review.wrong-signer"),
    ("breaks the review chain", "review.chain-break"),
    ("passed disagrees", "review.inconsistent"),
)
_OP_CODES["review.verify"] = _OP_CODES["review-gate.verify"] = _OP_CODES["review.bundle"]

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
    ("unsupported hash algorithm", "oid.hash-unsupported"),
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
    ("pack index checksum does not match", "localpack.index-checksum"),
    ("pack index is truncated or has trailing bytes", "localpack.index-length"),
    ("pack index entries are not sorted and unique", "localpack.index-order"),
    ("pack index block is oversized", "localpack.block-size"),
    ("run delta has no base before it", "localpack.delta-no-base"),
    ("packed run delta chain is too deep", "localpack.delta-too-deep"),
    ("packed object size does not match its index", "localpack.object-id-mismatch"),
    ("packed object does not match its id", "localpack.object-id-mismatch"),
    ("pack index entry is malformed", "localpack.encoding-kind"),
    ("slim event stores a default", "localpack.slim-default"),
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
