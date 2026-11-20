"""Behaviour flags and transcript clusters in the query index (0.74).

* ``transcript_flags``: one row per ``opentine.transcript-flag/1`` attestation
  (:mod:`opentine._transcript_flags`), held or not: the label, the evidence run
  ids (comma separated, sorted), the cluster id, the labeller and when;
* ``transcript_flag_runs``: one row per (flag, evidence run), to join with
  ``runs``;
* ``transcript_clusters``: one row per run, its cluster in the seeded k-means of
  :func:`opentine._transcript_cluster.kmeans` (default k, seed 0, the
  ``opentine.tfidf-hash/1`` space over the redacted runs), computed when the
  index is built and only while the repository holds at most
  :data:`CLUSTER_RUNS` runs (above that the table is empty; use ``tine
  transcripts cluster``).

``signed`` is 1 only when the Ed25519 signature verifies *and* the payload's
``signer`` names the key that signed. Under ``--verify`` a flag row is
``verified`` only for a pinned ``scorer`` or ``curator`` signer that does not
hold ``optimizer``; a cluster row is content-derived and never ``verified``.
Rows are derived and non-authoritative: ``tine transcripts flags`` decides.
"""

from __future__ import annotations

from typing import Any

CLUSTER_RUNS = 2000
COLUMNS: dict[str, tuple[str, ...]] = {
    "transcript_flags": ("oid", "target", "signer", "signed", "label", "evidence", "cluster",
                         "labeller", "labelled_at"),
    "transcript_flag_runs": ("oid", "run", "label"),
    "transcript_clusters": ("oid", "cluster", "size", "exemplar", "k", "seed",
                            "backend_digest"),
}  # fmt: skip
ROLES_FOR = {"transcript_flags": ("scorer", "curator")}
TABLES = ("transcript_flags",)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def attestation_rows(oid: str, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from opentine._query_containment import _signed
    from opentine._transcript_flags import CONVENTION

    claim = payload.get("claim")
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return {}
    evidence = claim.get("evidence")
    runs = sorted({e for e in evidence if isinstance(e, str)}) if isinstance(evidence, list) else []
    label = _text(claim.get("label"))
    row = {"oid": oid, "target": _text(payload.get("target_id")),
           "signer": _text(payload.get("signer")), "signed": _signed(payload), "label": label,
           "evidence": ",".join(runs), "cluster": _text(claim.get("cluster")),
           "labeller": _text(claim.get("labeller")),
           "labelled_at": _text(claim.get("labelled_at"))}  # fmt: skip
    return {
        "transcript_flags": [row],
        "transcript_flag_runs": [{"oid": oid, "run": r, "label": label} for r in runs],
    }


def cluster_rows(repo: Any, oids: list[str]) -> dict[str, list[dict[str, Any]]]:
    """``transcript_clusters`` rows (empty above :data:`CLUSTER_RUNS` runs or with none)."""
    runs = [o for o in oids if o.startswith("run:")]
    if not runs or len(runs) > CLUSTER_RUNS:
        return {"transcript_clusters": []}
    from opentine._transcript_cluster import kmeans
    from opentine._transcript_corpus import from_repo
    from opentine._transcript_space import Space

    space = Space(from_repo(repo))
    if not space.ids:
        return {"transcript_clusters": []}
    found = kmeans(space)
    digest = space.backend()["digest"]
    rows = [{"oid": run, "cluster": c["id"], "size": c["size"], "exemplar": c["exemplar"],
             "k": found["k"], "seed": found["seed"], "backend_digest": digest}
            for c in found["clusters"] for run in c["members"]]  # fmt: skip
    return {"transcript_clusters": sorted(rows, key=lambda r: r["oid"])}


__all__ = ["CLUSTER_RUNS", "COLUMNS", "ROLES_FOR", "TABLES", "attestation_rows", "cluster_rows"]
