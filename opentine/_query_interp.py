"""Interpretability custody records in the query index (0.83).

* ``interp_artifacts``: one row per ``opentine.interp-artifact/1`` attestation
  (:mod:`opentine._interp_custody`): the kind, the artifact and checkpoint
  digests, the blob, the layer and the custody tags;
* ``probe_calibrations``: one row per ``opentine.probe-calibration/1``
  attestation (:mod:`opentine._probe_monitor`): the probe, checkpoint, layer,
  threshold and the calibration counts.

``signed`` is 1 only when the Ed25519 signature verifies *and* the payload's
``signer`` names the key that signed. Under ``--verify`` an artifact row is
``verified`` only for a pinned ``runner`` signer and a calibration row only for
a pinned ``monitor`` or ``policy`` signer, never one that holds ``optimizer``.
Rows are derived and non-authoritative: ``tine interp check`` decides.
"""

from __future__ import annotations

from typing import Any

from opentine._query_values import integer as _int
from opentine._query_values import text as _text

COLUMNS: dict[str, tuple[str, ...]] = {
    "interp_artifacts": ("oid", "target", "signer", "signed", "kind", "digest", "blob", "size",
                         "checkpoint", "layer", "name", "tags", "recorded_at"),
    "probe_calibrations": ("oid", "target", "signer", "signed", "probe", "checkpoint", "layer",
                           "threshold", "n", "positives", "negatives", "true_positives",
                           "false_positives", "tpr", "fpr", "calibrated_at"),
}  # fmt: skip
ROLES_FOR = {"interp_artifacts": ("runner",), "probe_calibrations": ("monitor", "policy")}


def _num(value: Any) -> float | None:
    ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    return float(value) if ok else None


def attestation_rows(oid: str, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from opentine._interp_custody import CONVENTION
    from opentine._probe_monitor import CALIBRATION
    from opentine._query_containment import _signed

    claim = payload.get("claim")
    convention = claim.get("convention") if isinstance(claim, dict) else None
    if convention not in (CONVENTION, CALIBRATION):
        return {}
    head = {"oid": oid, "target": _text(payload.get("target_id")),
            "signer": _text(payload.get("signer")), "signed": _signed(payload)}  # fmt: skip
    if convention == CALIBRATION:
        row = {k: _text(claim.get(k)) for k in ("probe", "checkpoint", "calibrated_at")}
        row.update(
            {
                k: _int(claim.get(k))
                for k in (
                    "layer",
                    "n",
                    "positives",
                    "negatives",
                    "true_positives",
                    "false_positives",
                )
            }
        )
        row.update({k: _num(claim.get(k)) for k in ("threshold", "tpr", "fpr")})
        return {"probe_calibrations": [{**head, **row}]}
    tags = claim.get("tags")
    tags = ",".join(t for t in tags if isinstance(t, str)) if isinstance(tags, list) else None
    row = {
        k: _text(claim.get(k))
        for k in ("kind", "digest", "blob", "checkpoint", "name", "recorded_at")
    }
    return {
        "interp_artifacts": [
            {
                **head,
                **row,
                "size": _int(claim.get("size")),
                "layer": _int(claim.get("layer")),
                "tags": tags,
            }
        ]
    }


__all__ = ["COLUMNS", "ROLES_FOR", "attestation_rows"]
