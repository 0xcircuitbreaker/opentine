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
A tag counts only when its signer may record it: once key roles are pinned, a
`created` tag signed by a key with none of the `runner`, `policy` or `curator`
roles (an optimizer key) is ignored; with no pinned bundle every signed tag
counts. A claim whose location or digest is not a string is skipped on its own.
Matching is by whole token of the tool input (keys and values): a mark must not
be preceded or followed by a letter, digit, `_`, `.` or `-`, so `./ckpt/m.pt`
and `--ckpt=ckpt/m.pt` match `ckpt/m.pt` but a one-letter location does not
match every word. Trailing dots end a mark (Windows drops them from a path), so
`ckpt/m.pt.` matches while `ckpt/m.pt.bak` does not. A load through a
path no event names (a symlink, an alias, re-encoded bytes) is not seen. The
`loaded` events form the access log.

## Review and query (0.72)

Each call the gate denies is logged as a held blob
`opentine.weight-custody-refusal/1` (`artifact`, `reason`, `tool`, `at`; hold
`custody:weights-refused:NAME`, which `tine hold release` refuses). Writing the
log never changes the decision: a denial stands when the log cannot be written.

`tine oversight queue` lists, under the source `custody`, every event that a
`fail:` finding of `tine custody check` names, every held refusal and every
refused `tine organism gate` access (docs/OVERSIGHT.md). The items are
recomputed from the held records on each read; with no `custody` route they are
`unrouted` and are not listed. Approving an item records a review and does not
allow a load.

`tine query` indexes every custody attestation in the object store as
`weight_custody` and every organism tag, approval and untag as
`organism_records` (docs/QUERY.md). The rows are derived and non-authoritative.

## Export and copy quorum (0.91)

Once the owner-pinned trust bundle names any `custodian` key (key roles), or
carries a `custody` section (`tine trust bundle create --custody FILE`):

```json
{"version": 1, "k": 3}
```

a weight `copied` or `exported` event and a `tine interp export` need `k`
approvals (default 2; at least 2) from **distinct** custodian keys:

```
tine custody approve --operation copy|export --digest D --requester FPR --key KEY
                     [--checkpoint C] [--artifact NAME] [--destination TEXT]
tine custody revoke APPROVAL --key KEY
tine custody approvals --operation copy|export --digest D [--checkpoint C] --requester FPR
```

An approval is an attestation under `opentine.custody-approval/1`
(`operation`, `digest`, `checkpoint`, `requester`, `artifact`, `destination`,
`at`), held under `custody:quorum:approval:...` and never released. It covers
exactly one request:

- `digest`: the bytes copied or exported. Re-encoded bytes have another
  digest and need approvals of their own.
- `checkpoint`: what the bytes cover. For a weight artifact this is the digest
  of its `created` event; for an interpretability artifact, its checkpoint.
- `requester`: the fingerprint of the key that records the event (weights) or
  of `tine interp export --requester-key KEY`.

An approval counts only when it is signed by its key, that key is a pinned
`custodian` key that is not an `optimizer` key, it is not the requester's own
key, and it has not been revoked. A revocation (`opentine.custody-revocation/1`,
`{"approval", "at"}`) is signed by the approval's signer or a pinned `policy`
key. Approvals and revocations are read from the whole object store, so
dropping a hold row cannot hide a revocation. One custodian approving twice
counts once. A revocation counts whatever its `at` says: both dates are
claimed by their signers, so a copy dated before a revocation is still
reported once its approval is revoked (approve again to cover it).

A request short of its quorum is refused (`custody.quorum`, exit 1 from
`approvals`), and the refusal is held as an
`opentine.weight-custody-refusal/1` entry for the oversight queue. A copy or
export written around `tine custody record` (straight into the object store)
is reported by `tine custody check` as `fail:custody-copy-unapproved` when the
approvals it needed did not exist at its `recorded_at` time. Under a pinned
owner, a bundle that is missing or does not verify makes the quorum
impossible (fail closed). Without custodian keys or the section nothing
changes.

`tine interp calibrate` reads probe weights for scoring and is not an export.

Limits: distinct keys are counted, not distinct people; give each custodian
one key. Approvals carry no expiry; revoke an approval that is no longer
wanted.

## JSON

`--json` on `record --artifact`, `chain` and `check` prints
`tine-cli-custody-weights/1` (`docs/schemas/tine-cli-custody-weights-1.schema.json`);
on `approve`, `revoke` and `approvals` it prints `tine-cli-custody-quorum/1`
(0.91). The approval and revocation claims are published as
`opentine-custody-approval-1` and `opentine-custody-revocation-1`.
