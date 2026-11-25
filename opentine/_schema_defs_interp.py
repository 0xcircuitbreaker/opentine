"""JSON Schemas for interpretability custody and probe monitors (0.83).

``tine-cli-interp-1`` is the ``tine interp ... --json`` output. The artifact
record and the probe calibration are claims on attestations (an existing object
kind), published as ``opentine-interp-artifact-1`` and
``opentine-probe-calibration-1``; the probe weights format is
``opentine-linear-probe-1``. Conventions, not object kinds
(docs/INTERPRETABILITY.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, NUM, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-interp/1"}}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_BLOB = {"type": "string", "pattern": "^blob:sha256:[0-9a-f]{64}$"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_STATE = {"type": "string", "pattern": "^(verified|unverified: .+)$"}
_KIND = {"enum": ["attribution-graph", "sae-dashboard", "probe-weights"]}
_TAGS = {"type": "array", "items": {"enum": ["model-organism"]}}
_RATE = opt({"type": "number", "minimum": 0, "maximum": 1})
_UNIT = {"type": "number", "minimum": 0, "maximum": 1}
_ARTIFACT = {"kind": _KIND, "digest": _DIGEST, "blob": _BLOB, "size": INT,
             "checkpoint": _DIGEST, "layer": opt(INT), "name": opt(STR), "tags": _TAGS,
             "recorded_at": STR}  # fmt: skip
_ROW = closed(["record", "signer", "verification", *_ARTIFACT, "custody"], {
    "record": _ATT, "signer": opt(STR), "verification": _STATE, **_ARTIFACT,
    "custody": {"type": "array", "items": STR}})  # fmt: skip
_CAL = {"probe": _DIGEST, "checkpoint": _DIGEST, "layer": INT, "threshold": _UNIT, "n": INT,
        "positives": INT, "negatives": INT, "true_positives": INT, "false_positives": INT,
        "tpr": _RATE, "fpr": _RATE, "samples_digest": _DIGEST, "calibrated_at": STR}  # fmt: skip
_MONITOR = closed(["id", "kind", "model_digest", "probe", "checkpoint", "layer", "threshold",
                   "calibration"], {
    "id": STR, "kind": {"const": "probe"}, "model_digest": _DIGEST, "probe": _DIGEST,
    "checkpoint": _DIGEST, "layer": INT, "threshold": _UNIT, "calibration": opt(STR)})  # fmt: skip
_FINDING = closed(["code", "message"], {
    "code": {"enum": ["probe.calibration-missing", "probe.calibration-unverified",
                      "probe.swapped", "probe.threshold-changed", "probe.layer-changed",
                      "digest.mismatch"]}, "message": STR})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "record", "digest", "blob", "kind", "checkpoint"], {
        **_HEAD, "command": {"const": "interp store"}, "record": _ATT, "digest": _DIGEST,
        "blob": _BLOB, "kind": _KIND, "checkpoint": _DIGEST}),
    closed(["command", "schema", "artifacts"], {
        **_HEAD, "command": {"const": "interp list"},
        "artifacts": {"type": "array", "items": _ROW}}),
    closed(["command", "schema", "digest", "size", "out"], {
        **_HEAD, "command": {"const": "interp export"}, "digest": _DIGEST, "size": INT,
        "out": STR}),
    closed(["command", "schema", "record", *_CAL], {
        **_HEAD, "command": {"const": "interp calibrate"}, "record": _ATT, **_CAL}),
    closed(["command", "schema", "ok", "monitor", "findings"], {
        **_HEAD, "command": {"const": "interp check"}, "ok": BOOL, "monitor": _MONITOR,
        "findings": {"type": "array", "items": _FINDING}}),
    closed(["command", "schema", "score", "threshold", "over", "monitor"], {
        **_HEAD, "command": {"const": "interp score"}, "score": _UNIT, "threshold": _UNIT,
        "over": BOOL, "monitor": _MONITOR}),
]  # fmt: skip
_CLAIM = "A claim convention on an existing attestation, not an object kind."
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-interp-1": doc("tine-cli-interp-1", "tine interp ... --json",
        "Interpretability artifact custody, probe calibration and probe scores.",
        {"anyOf": _SHAPES}),
    "opentine-interp-artifact-1": doc("opentine-interp-artifact-1",
        "opentine.interp-artifact/1 claim",
        "An attribution graph, SAE feature dashboard or probe weights stored as a held "
        "blob keyed to a checkpoint digest. " + _CLAIM,
        closed(["convention", *_ARTIFACT], {
            "convention": {"const": "opentine.interp-artifact/1"}, **_ARTIFACT})),
    "opentine-probe-calibration-1": doc("opentine-probe-calibration-1",
        "opentine.probe-calibration/1 claim",
        "Calibration evidence binding a probe, checkpoint, layer and threshold. " + _CLAIM,
        closed(["convention", *_CAL], {
            "convention": {"const": "opentine.probe-calibration/1"}, **_CAL})),
    "opentine-linear-probe-1": doc("opentine-linear-probe-1", "opentine-linear-probe/1 weights",
        "The bytes of a probe-weights interpretability artifact: a format, not an object kind.",
        closed(["format", "layer", "weights"], {
            "format": {"const": "opentine-linear-probe/1"}, "layer": INT,
            "weights": {"type": "array", "items": NUM, "minItems": 1}, "bias": NUM})),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"interp {verb}": "tine-cli-interp-1"
    for verb in ("store", "list", "export", "calibrate", "check", "score")
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
