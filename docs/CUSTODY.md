# Checkpoint and weight custody

Since 0.71 a repository can keep a signed chain of custody for model checkpoints
and weights. This is separate from the evidence custody log of 0.39
(`tine custody record ACTION SUBJECT`, `tine custody log|verify`, docs/CLI.md),
which it sits beside under the same command.

## Weights by digest only

Weights never enter the repository. An artifact has a name (for example
`ckpt-7`), and each event records the SHA-256 digest and size of the bytes it
concerns. `--file PATH` reads the file in 1 MiB chunks to compute the digest and
stops with an error past `--max-bytes` (default 1 TiB); `--digest sha256:<hex>`
records a digest computed elsewhere. Nothing is uploaded by default.

## Events

```
tine custody record created s3://lab/ckpt-7 --artifact ckpt-7 --sign-key runner.key --file w.bin --run heads/train-7 --lineage node-3
tine custody record copied /scratch/ckpt-7 --artifact ckpt-7 --sign-key runner.key --file w.bin
tine custody record loaded /scratch/ckpt-7 --artifact ckpt-7 --sign-key runner.key --file w.bin
tine custody record destroyed /scratch/ckpt-7 --artifact ckpt-7 --sign-key runner.key
tine custody record approved review-42 --artifact ckpt-7 --sign-key policy.key --file w.bin
```

The positional after the event is the location (for `approved`, a free-text
reference to the approval). Every event is an **attestation** (an existing
object kind) with the claim convention `opentine.weight-custody/1`
(`docs/schemas/opentine-weight-custody-1.schema.json`):

| Field | Meaning |
| --- | --- |
| `artifact`, `event`, `location` | What happened, to which artifact, where |
| `digest`, `size` | The weight bytes (`size` only when computed from `--file`) |
| `seq`, `prev` | Position in the artifact's chain and the attestation id of the event before |
| `run` | The training run (resolved ref or run id) |
| `data` | Data commitments (`sha256:` digests, e.g. 0.60 holdout or dataset commitments) |
| `lineage` | The lineage node (0.58) |
| `tags` | `model-organism`, set only on the `created` event |
| `recorded_at` | RFC 3339 UTC |

The attestation's `signer` must be the fingerprint of the key that signed it
(`used_key_fingerprint`). Each event is kept by a hold
`custody:weights:<artifact>:<seq>`; `tine hold release` refuses these, so a
loop cannot delete a record of a copy or a load. This is a claim convention,
not a new object kind, and adds no `tine verify` codes.

## Roles

Roles come only from the owner-pinned trust bundle (docs/SECURITY_MODEL.md,
`_key_roles_pin`). Ordinary events need a `runner` key; `approved` events need a
`policy` key. An optimizer key never counts. An event whose signer has no pinned
role is reported as `advisory:custody.signer-unpinned`; an unpinned approval
never counts as an approval. Once roles are pinned, such an event also explains
nothing: a copy, move or destroy event signed by an optimizer key does not
account for a copy, so the gap it tries to cover is still reported. Without any
pinned trust bundle, events are only advisory.

## Checking

`tine custody chain NAME` lists the events and, for each, any chain problem and
its role state. `tine custody check NAME [--file LOCATION=PATH]... [--strict]`
exits 1 on any `fail:` finding. These are command-level codes:

| Code | When |
| --- | --- |
| `fail:custody-chain-broken` | An event is unsigned or not bound to its signer, malformed, out of `seq`, or its `prev` does not name the event before (for example a hold row was removed) |
| `fail:custody-gap` | No events; the first event is not `created`; a second `created`; a copy with a digest no event gave the artifact; a load or export from a location no event put it at, or with another digest (copied without a copy event); destroy at an unknown location; a `--file` observation at a location or digest no event explains |
| `fail:custody-unapproved-load` | A `model-organism` artifact was loaded before a valid approval of that digest |
| `advisory:custody.signer-unpinned` | The signer lacks the pinned role; blocks only with `--strict` |

A destroyed location is forgotten, so a later load from it is a gap.

## Model organisms and the load gate

Artifacts tagged `model-organism` (trained to misbehave, for research) need an
`approved` event, signed by a pinned `policy` key, for the digest being used.
`tine custody gate` is an agent `PreToolUse` hook: it reads one tool call on
stdin (Claude Code / Codex, or `{"protocol": "opentine-custody-gate/1", "tool":
{"name", "input"}}` with `--agent generic`) and denies the call when any string
in its input names a known location or digest of a tagged artifact whose
current digests are not all approved. It always prints one JSON object and
exits 0. It fails closed: an unreadable payload or repository denies, and so
does a tagged artifact whose held chain is broken or missing.

The gate does not trust the hold rows alone. It scans every signed
`opentine.weight-custody/1` attestation in the object store, so a tagged
`created` event keeps its artifact tagged after its hold row is dropped. The tag
follows the digest: the same bytes recorded under another artifact name are
tagged too. Destroy events never remove a location from what the gate matches.
Matching is by substring of the tool input (keys and values); a load through a
path no event names (a symlink, an alias, re-encoded bytes) is not seen. The
`loaded` events form the access log.

## JSON

`--json` on `record --artifact`, `chain` and `check` prints
`tine-cli-custody-weights/1` (`docs/schemas/tine-cli-custody-weights-1.schema.json`).
