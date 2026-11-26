"""Sealed segments, sampling audits and artifact provenance in the query index (0.84).

* ``ingest_segments``: one row per ``opentine.ingest-segment/1`` annotation
  (:mod:`opentine._rl_segment`): the stream, ``seq``, previous segment, the
  number of batches, the index range, the episode count, the signed Merkle
  ``root``, the op log index of the seal commitment and ``sealed_at``;
* ``ingest_audits``: one row per ``opentine.ingest-audit/1`` annotation
  (:mod:`opentine._rl_audit`): the segment, stream, root, population, the
  stated guarantee (``confidence``, ``max_bad``), the sample size checked, the
  counts ``ok``, ``missing`` and ``altered``, the source kind, the ``verdict``
  and ``at``;
* ``artifact_provenance``: one row per held provenance attestation
  (:mod:`opentine._artifact_provenance`) on a run: the subject, the artifact
  name, media type, canonical digest and size, the pointer slot, the C2PA store
  digest, the dataset version and ``created_at``.

``signed`` is 1 only when the Ed25519 signature verifies and the recorded
``signer`` is the key that signed. Under ``--verify`` a segment or provenance
row is ``verified`` only for a pinned ``runner`` signer and an audit row only
for a pinned ``auditor`` signer, never one that also holds ``optimizer``. Rows
are derived and non-authoritative: ``tine ingest segments`` and ``tine
provenance verify`` decide; failing segments and audits reach the oversight
queue as ``ingest`` items (:mod:`opentine._ingest_oversight`).
"""

from __future__ import annotations

from typing import Any

COLUMNS: dict[str, tuple[str, ...]] = {
    "ingest_segments": ("oid", "target", "signer", "signed", "stream", "seq", "previous",
                        "batches", "first_index", "next_index", "episodes", "root",
                        "log_index", "sealed_at"),
    "ingest_audits": ("oid", "target", "signer", "signed", "segment", "stream", "root",
                      "episodes", "confidence", "max_bad", "checked", "ok", "missing",
                      "altered", "source", "verdict", "at"),
    "artifact_provenance": ("oid", "target", "signer", "signed", "subject", "name", "media",
                            "digest", "size", "pointer", "c2pa", "dataset_version",
                            "created_at"),
}  # fmt: skip
ROLES_FOR = {"ingest_segments": ("runner",), "ingest_audits": ("auditor",),
             "artifact_provenance": ("runner",)}  # fmt: skip
TABLES = tuple(COLUMNS)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _int(value: Any) -> int | None:
    return value if type(value) is int else None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _segment(head: dict[str, Any], claim: dict[str, Any]) -> dict[str, Any]:
    batches = claim.get("batches")
    return {**head, "stream": _text(claim.get("stream")), "seq": _int(claim.get("seq")),
            "previous": _text(claim.get("previous")),
            "batches": len(batches) if isinstance(batches, list) else None,
            "first_index": _int(claim.get("first_index")),
            "next_index": _int(claim.get("next_index")),
            "episodes": _int(claim.get("episodes")), "root": _text(claim.get("root")),
            "log_index": _int(_dict(claim.get("log")).get("index")),
            "sealed_at": _text(claim.get("sealed_at"))}  # fmt: skip


def _audit(head: dict[str, Any], claim: dict[str, Any]) -> dict[str, Any]:
    guarantee = _dict(claim.get("guarantee"))
    return {**head, "segment": _text(claim.get("segment")), "stream": _text(claim.get("stream")),
            "root": _text(claim.get("root")), "episodes": _int(claim.get("episodes")),
            "confidence": _text(guarantee.get("confidence")),
            "max_bad": _text(guarantee.get("max_bad")), "checked": _int(claim.get("checked")),
            "ok": _int(claim.get("ok")), "missing": _int(claim.get("missing")),
            "altered": _int(claim.get("altered")),
            "source": _text(_dict(claim.get("source")).get("kind")),
            "verdict": _text(claim.get("verdict")), "at": _text(claim.get("at"))}  # fmt: skip


def annotation_rows(head: dict[str, Any], claim: dict[str, Any]) -> dict[str, list[dict]]:
    """Rows of a segment or audit claim (*head* holds ``oid``/``target``/``signer``/``signed``)."""
    from opentine._rl_audit import CONVENTION as AUDIT
    from opentine._rl_segment import CONVENTION as SEGMENT

    if claim.get("convention") == SEGMENT:
        return {"ingest_segments": [_segment(head, claim)]}
    if claim.get("convention") == AUDIT:
        return {"ingest_audits": [_audit(head, claim)]}
    return {}


def conventions() -> tuple[str, str]:
    from opentine._rl_audit import CONVENTION as AUDIT
    from opentine._rl_segment import CONVENTION as SEGMENT

    return SEGMENT, AUDIT


def attestation_rows(oid: str, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """The ``artifact_provenance`` row of a provenance attestation, else ``{}``."""
    from opentine._artifact_provenance import CONVENTION
    from opentine._query_containment import _signed

    claim = payload.get("claim")
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return {}
    artifact = _dict(claim.get("artifact"))
    return {"artifact_provenance": [{
        "oid": oid, "target": _text(payload.get("target_id")),
        "signer": _text(payload.get("signer")), "signed": _signed(payload),
        "subject": _text(claim.get("subject")), "name": _text(artifact.get("name")),
        "media": _text(artifact.get("media")), "digest": _text(artifact.get("digest")),
        "size": _int(artifact.get("size")), "pointer": _text(claim.get("pointer")),
        "c2pa": _text(claim.get("c2pa")), "dataset_version": _text(claim.get("dataset_version")),
        "created_at": _text(claim.get("created_at"))}]}  # fmt: skip


__all__ = ["COLUMNS", "ROLES_FOR", "TABLES", "annotation_rows", "attestation_rows",
           "conventions"]  # fmt: skip
