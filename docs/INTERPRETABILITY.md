# Interpretability custody and probe monitors (0.83)

opentine keeps interpretability artifacts under the same custody rules as the
checkpoints they describe, and lets a probe on a model's activations act as an
inline monitor. Nothing here adds an object kind or a `tine verify` code: every
record is a claim convention on an existing attestation (docs/FREEZE.md).

## Artifacts

Three kinds are stored:

| Kind | What it is |
| --- | --- |
| `attribution-graph` | an attribution graph computed on one checkpoint |
| `sae-dashboard` | an SAE feature dashboard (feature activations, top examples) |
| `probe-weights` | the weights of a probe, in the `opentine-linear-probe/1` format below |

```
tine interp store graph.json --kind attribution-graph --checkpoint sha256:<ckpt> --key runner.hex
tine interp list --checkpoint sha256:<ckpt>
tine interp export sha256:<artifact> --out graph.json --run <run>
```

The bytes are stored as a content-addressed **blob** and named by their own
`sha256:` digest. The record is an attestation whose claim is
`opentine.interp-artifact/1`:

```json
{"convention": "opentine.interp-artifact/1", "kind": "probe-weights",
 "digest": "sha256:...", "blob": "blob:sha256:...", "size": 1234,
 "checkpoint": "sha256:...", "layer": 12, "name": null, "tags": [],
 "recorded_at": "2026-12-05T10:00:00Z"}
```

The checkpoint is named by its digest only (docs/CUSTODY.md): weights are never
stored. The record and its blob are kept by `custody:interp:` holds that
`tine hold release` refuses, so a loop cannot delete either. A record counts as
signed only when the payload signer is the key that signed it, and as verified
only for a `runner` key in the owner-pinned trust bundle that is not an
`optimizer` key.

## Custody (0.72 rules, D13)

An artifact is under model-organism custody when:

- any held record of its bytes, or of any artifact keyed to the same checkpoint,
  carries the `model-organism` tag (`--tag model-organism`), so a second untagged
  record or a re-encoded or derived copy on that checkpoint stays under custody, or
- its own digest or its checkpoint's digest is tagged by `tine organism tag`, or
- the organism registry cannot be read (fail closed).

`tine interp export` (and `tine interp calibrate`, which reads probe weights)
then needs a valid `tine organism approve` record that binds the requesting run
to the artifact or to its checkpoint. Without one the read is refused with
`custody.denied` (exit 6) and nothing is written. Every read of a tagged
artifact, allowed or refused, is stored and held as an
`opentine.organism-access/1` entry, listed by `tine organism status`. Tagging the
checkpoint covers every artifact computed from it. Custody covers the
`tine interp` commands; a copy stored under a different checkpoint digest is a
different claim and is covered only when that digest is tagged.

Bytes are checked against their recorded digest on every read; a mismatch
fails with the existing `digest.mismatch` code (exit 4).

## Probe monitors

A probe monitor is a monitor of the 0.63 interface (docs/MONITORS.md) with
`kind = "probe"`. Its weights are a `probe-weights` artifact:

```json
{"format": "opentine-linear-probe/1", "layer": 12, "weights": [0.4, -1.2, ...], "bias": -0.1}
```

and its score is `sigmoid(weights . activations + bias)`.

```toml
version = 1
mode = "gate"
fail_closed = true           # required for a probe monitor in gate mode

[monitor]
id = "deception-probe"
kind = "probe"
probe = "sha256:<probe weights digest>"
probe_file = "probe.json"    # must hash to `probe`, or loading fails with digest.mismatch
checkpoint_digest = "sha256:<checkpoint>"
layer = 12
threshold = 0.5
calibration = "attestation:sha256:<calibration record>"
```

The harness puts the activations of the action being scored in the MCP request
under `params._meta["opentine/activations"]` as `{"checkpoint_digest",
"activations"}`; `activations` is a list or `{"LAYER": [...]}`. Activations from
any checkpoint other than `checkpoint_digest` are refused with the existing
`digest.mismatch` code, so the gate records `decided_by = "error"` and, failing
closed, blocks. Every verdict's `monitor` field records `probe`, `checkpoint`,
`layer`, `threshold` and `calibration`.

The gate checks a probe monitor against its calibration when it starts. A probe,
threshold, layer or checkpoint changed after calibration, or a calibration not
verified for a pinned `monitor` or `policy` key, makes every score an error, so
a gate blocks (it must fail closed) and an advisory monitor only records it.
`tine interp score` refuses the same way.

The activations must be put in the request by a trusted harness that reads the
model. The gate cannot tell activations a harness measured from activations the
agent wrote into its own request, so an agent that controls `params._meta`
controls what the probe sees.

### Calibration evidence

```
tine interp calibrate sha256:<probe> --threshold 0.5 --samples labelled.json --key monitor.hex
tine interp check monitor.toml
tine interp score monitor.toml --request request.json
```

`labelled.json` is a list of `{"activations": [...], "label": true|false}`.
The calibration is an attestation whose claim is `opentine.probe-calibration/1`:
`probe`, `checkpoint`, `layer`, `threshold`, `n`, `positives`, `negatives`,
`true_positives`, `false_positives`, `tpr`, `fpr`, `samples_digest` and
`calibrated_at`. It is held under `custody:interp-calibration:` and counts only
when signed by a pinned `monitor` or `policy` key that is not an `optimizer` key.

`tine interp check` compares a probe monitor's configuration with the
calibration it names and exits 1 on:

| Code | Meaning |
| --- | --- |
| `probe.calibration-missing` | no held calibration record with that id |
| `probe.calibration-unverified` | the calibration is not signed by a pinned `monitor` or `policy` key |
| `probe.swapped` | the probe digest differs from the calibrated one |
| `probe.threshold-changed` | the threshold differs from the calibrated one |
| `probe.layer-changed` | the layer differs from the calibrated one |
| `digest.mismatch` | the checkpoint differs from the calibrated one, or the probe file does not hash to its digest (exit 4) |

These are command-level codes, not `tine verify` codes.

## Query

`tine query index` adds two tables, `interp_artifacts` and `probe_calibrations`
(docs/QUERY.md). Under `--verify` an artifact row is verified only for a pinned
`runner` signer and a calibration row only for a pinned `monitor` or `policy`
signer, never one that holds `optimizer`. Rows are derived and
non-authoritative: `tine interp list` and `tine interp check` decide.

## Schemas

`tine-cli-interp-1` (command output), `opentine-interp-artifact-1`,
`opentine-probe-calibration-1` (claims) and `opentine-linear-probe-1` (probe
weights) are in docs/schemas.
