"""``tine verify --offline --locate``: where a broken run broke, honestly.

The artifact digest covers the whole body, so a mismatch alone says only "some
covered byte changed". Localisation uses the finer-grained evidence the file
and its companions really carry, and nothing else:

1. **Step ids.** Every step id is SHA-256 over the step's ``kind``, ``inputs``,
   ``outputs``, ``model_info``, ``tool_info``, ``error`` and ``parent_ids``
   (``_graph_types.step_id``). A step whose recomputed id differs from its
   stored id was edited in one of those fields; the hash cannot say which, so
   ``field_path`` names the step and ``covered_fields`` lists the candidates.
   Ids are computed before redaction, so a step whose stored content carries a
   ``[REDACTED`` marker cannot be rechecked and is skipped, not blamed.
2. **The stored action manifest** (``tine actions RUN --sign``): its
   ``run_digest`` covers the redacted step graph including the meters step ids
   leave out (timestamp, duration, cost, usage), and its per-entry digests
   name the tool step whose record changed.
3. **The claims cross-check**: when the run is intact but the stored manifest
   disagrees with it, the break is in the manifest entry (``manifest-entry``).
4. **An attestation subject** (``--attestation``): when the statement's digest
   equals the recomputed digest, the content is intact and the stored digest
   field itself was altered.

Anything else is ``locate.unlocalisable`` -- never a guess. ``byte_offset`` is
an offset into the canonical JSON of the *redacted, stored* body with the
``metadata`` key removed (the bytes the digest is computed over), not into the
file on disk, which may be compressed.
"""

from __future__ import annotations

from typing import Any

from opentine._canon import _canonical_bytes
from opentine._graph_types import StepKind, step_id

COVERED = ("kind", "inputs", "outputs", "model_info", "tool_info", "error", "parent_ids")
OFFSET_BASIS = "canonical JSON of the redacted stored body, metadata excluded"


def _result(region: str | None, reason: str, detail: str, **extra: Any) -> dict[str, Any]:
    out = {
        "localised": region is not None,
        "region": region,
        "reason": reason,
        "detail": detail,
        "step_index": None,
        "step_id": None,
        "field_path": None,
        "covered_fields": None,
        "byte_offset": None,
        "byte_offset_basis": OFFSET_BASIS,
    }
    out.update(extra)
    return out


def _recomputed(step: dict[str, Any]) -> str | None:
    try:
        return step_id(
            StepKind(step.get("kind")),
            step.get("inputs") or {},
            parent_ids=list(step.get("parent_ids") or []),
            outputs=step.get("outputs") or {},
            model_info=step.get("model_info") or "",
            tool_info=step.get("tool_info") or {},
            error=step.get("error") or {},
        )
    except (TypeError, ValueError, RecursionError):
        return None


def _offset(body: bytes, key: str) -> int | None:
    found = body.find(b'"' + key.encode("utf-8") + b'":{')
    return found if found >= 0 else None


def broken_step(data: dict[str, Any]) -> dict[str, Any] | None:
    """The first step (in graph order) whose recomputed id differs, else ``None``."""
    graph = data.get("graph") if isinstance(data.get("graph"), dict) else {}
    steps = graph.get("steps") if isinstance(graph.get("steps"), dict) else {}
    order = graph.get("order") if isinstance(graph.get("order"), list) else list(steps)
    body = _canonical_bytes({k: v for k, v in data.items() if k != "metadata"})
    for index, key in enumerate(order):
        step = steps.get(key) if isinstance(key, str) else None
        if not isinstance(step, dict):
            continue
        if b"[REDACTED" in _canonical_bytes(step):
            continue  # ids hash pre-redaction content: unverifiable, never blamed
        stored = step.get("id")
        fresh = _recomputed(step)
        if fresh is not None and stored == key and fresh == stored:
            continue
        path = f"graph.steps.{key}" + (".id" if stored != key else "")
        return _result(
            "step",
            "locate.step-id-mismatch" if stored == key else "locate.step-key-mismatch",
            f"step {index} no longer hashes to its id (recomputed {fresh})",
            step_index=index,
            step_id=key,
            field_path=path,
            covered_fields=list(COVERED),
            byte_offset=_offset(body, key),
        )
    return None


def _manifest_region(data: dict[str, Any], stored: Any, run: Any) -> dict[str, Any] | None:
    from opentine._actions_manifest import build_body

    if not isinstance(stored, dict) or not isinstance(stored.get("body"), dict) or run is None:
        return None
    try:
        fresh = build_body(run)
    except Exception:
        return None
    claimed = stored["body"]
    if claimed.get("run_id") != fresh["run_id"] or claimed.get("run_digest") == fresh["run_digest"]:
        return None
    old = {e.get("step_id"): e.get("digest") for e in claimed.get("entries") or []}
    order = data.get("graph", {}).get("order") or []
    body = _canonical_bytes({k: v for k, v in data.items() if k != "metadata"})
    for entry in fresh["entries"]:
        if old.get(entry["step_id"]) not in (None, entry["digest"]):
            index = order.index(entry["step_id"]) if entry["step_id"] in order else None
            return _result(
                "step",
                "locate.action-digest-mismatch",
                "the tool step's recorded action no longer matches its manifest entry",
                step_index=index,
                step_id=entry["step_id"],
                field_path=f"graph.steps.{entry['step_id']}",
                byte_offset=_offset(body, entry["step_id"]),
            )
    return _result(
        "step-meters",
        "locate.graph-meters-changed",
        "step ids verify but the manifest's graph digest differs: a timestamp, duration, "
        "cost or usage field changed (the manifest cannot say which step)",
        field_path="graph",
    )


def locate(
    data: Any,
    integrity: Any,
    *,
    signature_ok: bool | None = None,
    manifest: Any = None,
    run: Any = None,
    attested_digest: str | None = None,
    claims: Any = None,
) -> dict[str, Any]:
    """The localisation object for one artifact (see the module docstring)."""
    if integrity.ok:
        if claims is not None and claims.outcome == "fail":
            return _result(
                "manifest-entry",
                "locate.manifest-entry",
                f"the run is intact; the stored action manifest disagrees: {claims.detail}",
                field_path="action-manifest.body.entries",
            )
        if signature_ok is False:
            return _result(
                "signature",
                "locate.signature",
                "the digest matches, so the break is in the signed metadata or the "
                "signature block (metadata is outside the digest)",
                field_path="metadata",
            )
        return _result(None, "locate.nothing-to-locate", "every check that can fail passed")
    if not isinstance(data, dict):
        return _result(None, "locate.unreadable", f"artifact cannot be parsed: {integrity.reason}")
    if integrity.reason in ("malformed digest", "missing integrity digest"):
        return _result(
            "digest", "locate.digest-malformed", integrity.reason, field_path="metadata.integrity"
        )
    if integrity.reason != "digest mismatch":
        return _result(None, "locate.unlocalisable", str(integrity.reason))
    found = broken_step(data) or _manifest_region(data, manifest, run)
    if found is not None:
        return found
    if attested_digest and attested_digest == integrity.actual:
        return _result(
            "digest",
            "locate.digest-field",
            "the content matches the attestation subject: the stored digest itself changed",
            field_path="metadata.integrity.digest",
        )
    return _result(
        None,
        "locate.unlocalisable",
        "every step still hashes to its id; the change is in the digest field or a part of "
        "the body no finer-grained hash covers (status, refs, transcript, meters, ...)",
    )


__all__ = ["COVERED", "OFFSET_BASIS", "broken_step", "locate"]
