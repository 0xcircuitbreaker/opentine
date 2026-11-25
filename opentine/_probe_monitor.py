"""Interpretability-backed monitors (0.83): the ``probe`` monitor class.

A probe monitor scores an action from the model's internal activations instead
of its text. Its weights are an interpretability artifact
(:mod:`opentine._interp_custody`, kind ``probe-weights``) in the
``opentine-linear-probe/1`` format::

    {"format": "opentine-linear-probe/1", "layer": INT, "weights": [NUM, ...], "bias": NUM}

and its score is ``sigmoid(weights . activations + bias)``. The request it
scores carries ``checkpoint_digest`` (the model the activations came from) and
``activations`` (a list, or ``{"LAYER": [...]}``). A request from any other
checkpoint than the probe's is refused with the existing ``digest.mismatch``
code: a probe read on the wrong model says nothing.

Calibration evidence is an attestation (an existing object kind) whose claim
names the convention ``opentine.probe-calibration/1``::

    {"convention", "probe", "checkpoint", "layer", "threshold", "n", "positives",
     "negatives", "true_positives", "false_positives", "tpr", "fpr",
     "samples_digest", "calibrated_at"}

held under ``custody:interp-calibration:``. It counts only when signed by a pinned
``monitor`` or ``policy`` key that is not an ``optimizer`` key. :func:`check`
compares a monitor configuration with its calibration and reports a swapped
probe, a changed threshold, layer or checkpoint, or a missing or unverified
calibration; a gate fails closed on any of them.
"""

from __future__ import annotations

import math
import time
from typing import Any

from opentine import _containment_records as records
from opentine import _interp_custody as ic
from opentine._monitor_verdict import digest as json_digest

FORMAT = "opentine-linear-probe/1"
CALIBRATION = "opentine.probe-calibration/1"
HOLD = "custody:interp-calibration:"
ROLES = ("monitor", "policy")
MAX_WIDTH = 1 << 20
MAX_SAMPLES = 100_000


class ProbeError(ValueError):
    """Probe weights, a request or a calibration that cannot be used."""

    code = "probe.invalid"


class ProbeMismatch(ProbeError):
    """Activations from another checkpoint than the probe's."""

    code = ic.MISMATCH


def _num(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def parse(data: bytes) -> dict[str, Any]:
    """The checked probe: ``{"layer", "weights", "bias"}``."""
    from opentine import _json_shallow

    try:
        doc = _json_shallow.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProbeError(f"probe weights are not JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise ProbeError(f"probe weights are a {FORMAT} object")
    weights, bias, layer = doc.get("weights"), doc.get("bias", 0.0), doc.get("layer")
    if not isinstance(weights, list) or not 0 < len(weights) <= MAX_WIDTH:
        raise ProbeError(f"probe weights are a list of 1..{MAX_WIDTH} numbers")
    if not all(_num(w) for w in weights) or not _num(bias):
        raise ProbeError("probe weights and bias are finite numbers")
    if type(layer) is not int or layer < 0:
        raise ProbeError("a probe names its layer as a non-negative integer")
    return {"layer": layer, "weights": [float(w) for w in weights], "bias": float(bias)}


def apply(probe: dict[str, Any], activations: Any) -> float:
    """``sigmoid(w . x + b)`` of one activation vector."""
    if isinstance(activations, dict):
        activations = activations.get(str(probe["layer"]))
    if not isinstance(activations, list) or len(activations) != len(probe["weights"]):
        raise ProbeError(f"activations are a list of {len(probe['weights'])} numbers")
    if not all(_num(a) for a in activations):
        raise ProbeError("activations are finite numbers")
    z = sum(w * a for w, a in zip(probe["weights"], activations, strict=True)) + probe["bias"]
    return 1.0 / (1.0 + math.exp(-z)) if z >= 0 else math.exp(z) / (1.0 + math.exp(z))


class ProbeMonitor:
    """A monitor of the 0.63 interface whose ``kind`` is ``probe``."""

    def __init__(self, ident: str, data: bytes, *, probe: str, checkpoint: str, layer: int,
                 threshold: float, calibration: str | None) -> None:  # fmt: skip
        if ic.digest(data) != probe:
            raise ProbeMismatch(f"{ic.MISMATCH}: the probe file is not {probe}")
        self.probe = parse(data)
        if self.probe["layer"] != layer:
            raise ProbeError(f"the probe reads layer {self.probe['layer']}, not {layer}")
        self.checkpoint, self.threshold = checkpoint, float(threshold)
        self.identity = {"id": ident, "kind": "probe", "model_digest": probe, "probe": probe,
                         "checkpoint": checkpoint, "layer": layer, "threshold": self.threshold,
                         "calibration": calibration}  # fmt: skip

    def score(self, request: dict[str, Any]) -> dict[str, Any]:
        got = request.get("checkpoint_digest")
        if got != self.checkpoint:
            raise ProbeMismatch(f"{ic.MISMATCH}: activations come from {got!r}, the probe was "
                                f"fitted on {self.checkpoint}")  # fmt: skip
        return {"score": apply(self.probe, request.get("activations"))}


def calibrate(repo: Any, probe: str, key: Any, *, threshold: float,
              samples: list[dict[str, Any]], run: str | None = None,
              now: float | None = None) -> dict[str, Any]:  # fmt: skip
    """Score labelled *samples*, sign and hold the calibration; ``{"record", "claim"}``."""
    if not _num(threshold) or not 0 <= threshold <= 1:
        raise ProbeError("a threshold is between 0 and 1")
    if not isinstance(samples, list) or not 0 < len(samples) <= MAX_SAMPLES:
        raise ProbeError(f"calibration needs 1..{MAX_SAMPLES} labelled samples")
    data, row = ic.export(repo, probe, run=run, tool="tine interp calibrate")
    if row["kind"] != "probe-weights":
        raise ProbeError(f"{probe} is a {row['kind']}, not probe weights")
    weights = parse(data)
    tp = fp = pos = 0
    for sample in samples:
        if not isinstance(sample, dict) or type(sample.get("label")) is not bool:
            raise ProbeError('a sample is {"activations": [...], "label": true|false}')
        hit = apply(weights, sample.get("activations")) >= threshold
        pos += sample["label"]
        tp += hit and sample["label"]
        fp += hit and not sample["label"]
    neg = len(samples) - pos
    claim = {"convention": CALIBRATION, "probe": probe, "checkpoint": row["checkpoint"],
             "layer": weights["layer"], "threshold": float(threshold), "n": len(samples),
             "positives": pos, "negatives": neg, "true_positives": tp, "false_positives": fp,
             "tpr": tp / pos if pos else None, "fpr": fp / neg if neg else None,
             "samples_digest": json_digest(samples),
             "calibrated_at": records.rfc3339(time.time() if now is None else now)}  # fmt: skip
    target = records.anchor(repo, "interp", f"{CALIBRATION} {probe}")
    hold = f"{HOLD}{probe.removeprefix('sha256:')}:{claim['samples_digest'][-16:]}"
    return {"record": records.record(repo, target, claim, key, hold), "claim": claim}


def calibrations(repo: Any) -> list[dict[str, Any]]:
    out = []
    for _target, row in records.held(repo, HOLD):
        claim = row["claim"]
        if not isinstance(claim, dict) or claim.get("convention") != CALIBRATION:
            continue
        state = _role(repo, row)
        out.append({"record": row["oid"], "signer": row["signer"], "verification": state,
                    "claim": claim})  # fmt: skip
    return out


def _role(repo: Any, row: dict[str, Any]) -> str:
    if not row["signed"]:
        return "unverified: not signed by the key its signer field names"
    states = [records.role_state(repo, row["signer"], r) for r in ROLES]
    return "verified" if "verified" in states else states[0]


def check(repo: Any, identity: dict[str, Any]) -> list[dict[str, str]]:
    """Findings for a probe monitor *identity* against its calibration (none: sound)."""
    oid = identity.get("calibration")
    rows = [r for r in calibrations(repo) if r["record"] == oid]
    if not oid or not rows:
        return [{"code": "probe.calibration-missing",
                 "message": f"no held calibration record {oid!r}"}]  # fmt: skip
    row, out = rows[0], []
    if row["verification"] != "verified":
        out.append({"code": "probe.calibration-unverified", "message": row["verification"]})
    claim = row["claim"]
    pairs = (("probe", "probe", "probe.swapped"), ("threshold", "threshold",
             "probe.threshold-changed"), ("layer", "layer", "probe.layer-changed"),
             ("checkpoint", "checkpoint", ic.MISMATCH))  # fmt: skip
    for mine, theirs, code in pairs:
        if identity.get(mine) != claim.get(theirs):
            out.append({"code": code, "message": f"{mine} is {identity.get(mine)!r}; it was "
                        f"calibrated as {claim.get(theirs)!r}"})  # fmt: skip
    return out


__all__ = ["CALIBRATION", "FORMAT", "HOLD", "ProbeError", "ProbeMismatch", "ProbeMonitor",
           "apply", "calibrate", "calibrations", "check", "parse"]  # fmt: skip
