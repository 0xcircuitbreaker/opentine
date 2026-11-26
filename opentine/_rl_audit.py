"""Commit-then-reveal sampling audits of sealed segments (0.84): ``opentine.ingest-audit/1``.

The segment root is committed first: it is in the op log at the seal entry
``K`` (:mod:`opentine._rl_segment`). The sample seed is revealed later: it is
``SHA-256("opentine.ingest-audit/1" 0x00 SEGMENT-ID 0x00 R)``, where ``R`` is
the op log's Merkle root at size ``K + 2`` -- the first log tree strictly later
than the seal. No one choosing what to seal can know ``R``, and the auditor has
no choice of checkpoint: ``R`` is fixed once entry ``K + 1`` exists. The signed
checkpoint the audit reads (``--checkpoint FILE``, else the log's own) must
be signed by the log key, have size above ``K + 1`` and agree with the log's
entries (a forked or ahead-of-log checkpoint is ambiguous and refused).

The sample size is chosen from the stated guarantee (:func:`opentine._rl_merkle.sample_size`).
Each sampled episode is looked up in the audited source -- the repository's
batches, or ``--episodes FILE`` (JSON Lines of stored lines, e.g. a training
set exported from the stream) -- and checked against the signed root with an
RFC 9162 inclusion proof: absent is ``missing``, a proof that fails is ``altered``.
The verdict is a signed ``annotation`` on the segment (no new kind), held as
``ingest-audit:SEGMENT``; its signer must hold the pinned ``auditor`` role and
no ``optimizer`` role.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from opentine import _ingest_holds, _rl_merkle, _rl_segment
from opentine._ingest_policy import IngestError
from opentine.repository import _oplog, _tlog, _tlog_note, _tlog_proof
from opentine.repository._holds import INGEST_AUDIT

CONVENTION = "opentine.ingest-audit/1"
MAX_FAILURES = 1000


def judge_auditor(signer: str | None, roles: dict[str, Any]) -> str | None:
    """``None`` when *signer* may sign audits: a pinned ``auditor`` key, never an optimizer."""
    if signer is None:
        return "ingest.audit-unsigned"
    if roles.get("status") != "pinned":
        return "ingest.policy-unpinned"
    held = roles.get("roles") or {}
    if signer in held.get("optimizer", []):
        return "ingest.audit-optimizer-key"
    return None if signer in held.get("auditor", []) else "ingest.audit-role"


def basis(repo: Any, segment: dict[str, Any], note: bytes | None = None) -> dict[str, Any]:
    """The seed basis: the op log tree at the seal index + 2, proven by a signed checkpoint."""
    claim, log = segment["claim"], segment["claim"].get("log")
    seal = log.get("index") if isinstance(log, dict) else None
    if not isinstance(seal, int) or isinstance(seal, bool) or log.get("origin") != _oplog.ORIGIN:
        raise IngestError("the segment names no op log seal entry")
    root_dir = _oplog.log_root(repo.path)
    note = (root_dir / "checkpoint").read_bytes() if note is None else note
    _, size, signed_root = _tlog_note.open_checkpoint(note, _tlog_note.stored_vkey(root_dir))
    if size <= seal + 1:
        raise IngestError(f"checkpoint size {size} is not later than the seal (entry {seal}): "
                          "the log needs an entry after the seal first")  # fmt: skip
    entries = _tlog_note.verify_log(root_dir, _oplog.ORIGIN)
    leaves = [_tlog.leaf_hash(e) for e in entries]
    if len(entries) < size or _tlog.merkle_root(leaves[:size]) != signed_root:
        raise IngestError("the checkpoint is ambiguous: it disagrees with the op log")
    if not _rl_segment.committed_in(entries, claim):
        raise IngestError(f"op log entry {seal} does not commit to this segment's root")
    later = seal + 2
    return {"origin": _oplog.ORIGIN, "seal_index": seal, "size": later,
            "root": _tlog.merkle_root(leaves[:later]).hex(),
            "note": note.decode("utf-8")}  # fmt: skip


def seed(segment_id: str, tree_root_hex: str) -> str:
    raw = CONVENTION.encode() + b"\x00" + segment_id.encode() + b"\x00"
    return hashlib.sha256(raw + bytes.fromhex(tree_root_hex)).hexdigest()


def file_leaves(data: bytes) -> dict[int, bytes | None]:
    """Episode leaf per index from JSON Lines of stored lines (``None``: conflicting copies)."""
    from opentine._ingest_batch import _LINE, _pairs
    from opentine._json_shallow import loads

    out: dict[int, bytes | None] = {}
    for number, line in enumerate(data.split(b"\n"), 1):
        if not line.strip():
            continue
        try:
            row = loads(line.decode("utf-8"), object_pairs_hook=_pairs)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise IngestError(f"episodes line {number} is not JSON: {exc}") from exc
        index = row.get("i") if isinstance(row, dict) else None
        if isinstance(index, bool) or not isinstance(index, int):
            raise IngestError(f"episodes line {number} has no integer index i")
        leaf = _rl_merkle.episode_leaf(_LINE.encode(row).encode("utf-8"))
        out[index] = leaf if out.get(index, leaf) == leaf else None
    return out


def _load(repo: Any, segment_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    from opentine._ingest_policy import judge_writer
    from opentine._key_roles_pin import resolve

    segment = _rl_segment.read(repo, segment_id)
    if segment is None or not segment["signed"]:
        raise IngestError(f"{segment_id} is not a signed segment")
    claim = segment["claim"]
    if judge_writer(segment["signer"], resolve(repo.path)):
        raise IngestError(f"{segment_id} is not sealed by a pinned runner key")
    found = _rl_segment.episodes(repo, claim.get("stream"), claim.get("batches") or [])
    root = "sha256:" + _rl_merkle.Tree(found["leaves"]).root().hex()
    if (
        found["problems"]
        or root != claim.get("root")
        or len(found["leaves"]) != claim.get("episodes")
    ):
        raise IngestError(f"{segment_id}: the root does not match its batches")
    return segment, found


def evaluate(repo: Any, segment_id: str, *, confidence: str, max_bad: str,
             checkpoint: bytes | None = None,
             source: bytes | None = None) -> dict[str, Any]:  # fmt: skip
    """The unsigned verdict claim (without ``at``): sample and check one segment."""
    conf = _rl_merkle.fraction(confidence, "confidence", low_open=True)
    bad = _rl_merkle.fraction(max_bad, "max-bad", low_open=False)
    segment, found = _load(repo, segment_id)
    claim = segment["claim"]
    picked = basis(repo, segment, checkpoint)
    sample_seed = seed(segment_id, picked["root"])
    population = len(found["leaves"])
    bound = _rl_merkle.sample_size(population, conf, bad)
    positions = _rl_merkle.sample(sample_seed, population, bound["sample"])
    tree = _rl_merkle.Tree(found["leaves"])
    root = tree.root()
    lookup = file_leaves(source) if source is not None else None
    counts, failures = {"ok": 0, "missing": 0, "altered": 0}, []
    for position in positions:
        index = found["indexes"][position]
        leaf = found["leaves"][position] if lookup is None else lookup.get(index, b"")
        status = "missing" if leaf == b"" else "ok"
        if status == "ok":
            proof = _tlog_proof.inclusion_proof(tree, position)
            try:
                _tlog_proof.verify_inclusion(leaf or b"", position, population, proof, root)
            except (_tlog.LogError, TypeError):
                status = "altered"
        counts[status] += 1
        if status != "ok" and len(failures) < MAX_FAILURES:
            failures.append({"position": position, "index": index, "status": status})
    src = ({"kind": "repository"} if source is None else
           {"kind": "file", "sha256": "sha256:" + hashlib.sha256(source).hexdigest()})  # fmt: skip
    return {"convention": CONVENTION, "segment": segment_id, "stream": claim["stream"],
            "root": claim["root"], "episodes": population,
            "guarantee": {"confidence": str(confidence), "max_bad": str(max_bad)},
            "bound": {"method": "hypergeometric", **bound}, "checkpoint": picked,
            "seed": sample_seed, "positions": _rl_merkle.positions_digest(positions),
            "source": src, "checked": len(positions), **counts, "failures": failures,
            "verdict": "pass" if counts["ok"] == len(positions) else "fail"}  # fmt: skip


def run(repo: Any, segment_id: str, key: Any, *, confidence: str, max_bad: str, at_ms: int,
        checkpoint: bytes | None = None,
        source: bytes | None = None) -> dict[str, Any]:  # fmt: skip
    """Sample, check and sign one audit of a segment; its ``id`` and claim."""
    from opentine._key_roles_pin import resolve
    from opentine._signing_pins import key_fingerprint
    from opentine.repository import _write_batch

    signer = key_fingerprint(key.public_key().public_bytes_raw())
    code = judge_auditor(signer, resolve(repo.path))
    if code:
        raise IngestError(f"this key may not sign audits ({code}): a pinned auditor key, "
                          "never an optimizer key")  # fmt: skip
    verdict = evaluate(repo, segment_id, confidence=confidence, max_bad=max_bad,
                       checkpoint=checkpoint, source=source)  # fmt: skip
    at = datetime.fromtimestamp(at_ms / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    verdict["at"] = at
    with _write_batch.batched(repo):
        oid = _ingest_holds.write(repo, segment_id, verdict, key, previous=None, signed_at=at)
    _ingest_holds.hold(repo, INGEST_AUDIT + segment_id, oid)
    return {"id": oid, **verdict}


def prove(repo: Any, segment_id: str, index: int) -> dict[str, Any]:
    """A self-contained inclusion proof of the episode at stream *index* in a segment."""
    segment, found = _load(repo, segment_id)
    if index not in found["indexes"]:
        raise IngestError(f"index {index} is not a captured episode of {segment_id}")
    position = found["indexes"].index(index)
    tree = _rl_merkle.Tree(found["leaves"])
    proof = _tlog_proof.inclusion_proof(tree, position)
    return {"segment": segment_id, "root": segment["claim"]["root"], "size": tree.size,
            "position": position, "index": index, "leaf": found["leaves"][position].hex(),
            "proof": [h.hex() for h in proof]}  # fmt: skip


def check_proof(doc: dict[str, Any], line: bytes) -> bool:
    """Whether *line* is the episode *doc* proves under its root (no repository needed)."""
    try:
        root = bytes.fromhex(str(doc["root"]).removeprefix("sha256:"))
        proof = [bytes.fromhex(h) for h in doc["proof"]]
        leaf = _rl_merkle.episode_leaf(line.rstrip(b"\n"))
        _tlog_proof.verify_inclusion(leaf, doc["position"], doc["size"], proof, root)
    except (KeyError, TypeError, ValueError):
        return False
    return True


__all__ = ["CONVENTION", "basis", "check_proof", "evaluate", "file_leaves", "judge_auditor",
           "prove", "run", "seed"]  # fmt: skip
