"""A run's scaffold manifest as a signed, held record (0.88).

``tine agent scaffold --record RUN --key KEY --repo PATH`` signs the manifest
onto the stored run as an existing ``attestation`` whose claim follows the
``opentine.scaffold-manifest/1`` convention (the manifest plus ``run``), and
holds it under ``scaffold-manifest:RUN``, which ``tine hold release`` refuses,
so a loop cannot delete the record of the scaffold it ran with.

The claim must survive the credential scrubber unchanged: a path that reads as
a credential would be rewritten before signing and the tree digest could never
be recomputed, so such a manifest is refused (``scaffold.redaction``) rather
than stored altered.

A harness capture also records ``metadata.scaffold`` on the run: the schema,
harness, source, file count and ``tree_sha256`` (digests only, never content).
"""

from __future__ import annotations

from typing import Any

from opentine._scaffold_files import ScaffoldError
from opentine._scaffold_manifest import SCHEMA, build, tree_digest
from opentine.repository._holds import SCAFFOLD as HOLD


def claim(manifest: dict[str, Any], run: str) -> dict[str, Any]:
    from opentine._v3_guards import guarded_redaction

    body = {"convention": SCHEMA, "run": run, **manifest}
    if guarded_redaction(body, where="v3 'attestation'") != body:
        raise ScaffoldError("scaffold.redaction", "a scaffold path or link reads as a "
                            "credential; the manifest would be stored altered")  # fmt: skip
    return body


def record(repo: Any, run: str, manifest: dict[str, Any], key: Any) -> str:
    """Sign *manifest* onto the stored run *run* and hold it; the attestation id."""
    from opentine import _containment_records as records

    return records.record(repo, run, claim(manifest, run), key, HOLD + run)


def recorded(repo: Any, run: str) -> list[dict[str, Any]]:
    """The held manifests of *run*: ``{oid, signer, signed, tree_ok, claim}`` each."""
    from opentine import _containment_records as records

    out = []
    for target, row in records.held(repo, HOLD + run):
        body = row.get("claim")
        if target != HOLD + run or row.get("target") != run:  # a prefix, or another run's
            continue
        if not isinstance(body, dict) or body.get("convention") != SCHEMA:
            continue
        if body.get("run") != run:  # a manifest replayed from another run
            continue
        files = body.get("files")
        ok = isinstance(files, list) and tree_digest(files) == body.get("tree_sha256")
        out.append({"oid": row["oid"], "signer": row["signer"], "signed": row["signed"],
                    "tree_ok": ok, "claim": body})  # fmt: skip
    return out


def summary(harness: str, root: Any = ".") -> dict[str, Any] | None:
    """``metadata.scaffold`` for a capture; ``None`` when no manifest can be built."""
    try:
        found = build(harness, root)
    except (ScaffoldError, OSError):
        return None
    return {"schema": SCHEMA, "harness": harness, "source": found["source"],
            "files": len(found["files"]), "tree_sha256": found["tree_sha256"]}  # fmt: skip


__all__ = ["HOLD", "claim", "record", "recorded", "summary"]
