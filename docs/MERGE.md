# Merging run histories

Parallel self-improving loops run on separate branches or separate remotes.
Each one moves refs, promotes runs to labels, records lineage variants and
adds holds (loop stops, integrity taints, memory quarantines). When the
populations converge, those histories have to be merged without losing a stop
or a taint that one side added.

OpenTine has two merge commands:

- `tine merge OURS THEIRS` merges two **runs** into one merge run (0.47, SPEC
  4.19, design note `docs/design/F2-merge.md`).
- `tine merge-history` (0.69) merges what loops hold **around** runs: refs,
  labels, lineage records and holds. This page describes it.

## Snapshots

A snapshot (`opentine-history-snapshot/1`) is what one branch or remote
holds:

```json
{"format": "opentine-history-snapshot/1",
 "refs":    {"heads/main": "run:sha256:…"},
 "labels":  {"prod": {"current": "run:sha256:…", "history": ["<sha256 of each decision row>"]}},
 "lineage": {"sha256:<variant>": "<sha256 of the record file>"},
 "holds":   [["integrity-taint:run:sha256:…", "attestation:sha256:…"]]}
```

`tine merge-history snapshot [--repo PATH] [--state DIR] [--lineage DIR]`
prints the snapshot of a repository: its `heads/` and `tags/` refs, the label
states under `.tine/promotion`, the variant records under `.tine/lineage` and
the rows of `.tine/holds`. Save one when two loops fork; it is the base of the
later merge. Its digest is `sha256:` over `opentine.history-snapshot.v1:` and
the JCS of the snapshot.

## The merge

`tine merge-history plan --base BASE.json --theirs THEIRS.json` merges the
base, this repository's own snapshot and the other side's snapshot. Per key:

- unchanged on one side takes the other side's value;
- the same change on both sides is taken once;
- anything else is a conflict, and the key keeps the **base** value.

Refs and lineage records are append-only: a ref or record missing on one side
is not a deletion, so a merge never deletes either. Holds are the union of all
three snapshots: a merge never removes a hold.

The merge is symmetric. A conflict lists its two side values sorted, never as
"ours" and "theirs", so `merge(base, a, b)` and `merge(base, b, a)` give the
same merged snapshot, the same digests and the same conflicts. Conflicts are
sorted by kind, then key.

### Conflict kinds

| Kind | When |
| --- | --- |
| `ref-diverged` | Both sides moved a ref to different objects. |
| `label-moved` | Both sides moved a label to different runs. |
| `promotion-diverged` | The label's decision histories do not extend each other (or one side rewrote the base history). |
| `lineage-id` | One variant id names two different record files. |
| `hold-weakened` | A hold of the base is missing on one side. The hold is kept. |
| `held-target` | A ref or label moved onto an object that a `loop-stop:`, `integrity-taint:` or `memory-quarantine:` hold in the base or on either side names. The ref or label stays at its base value. |

No conflict is resolved in favour of the side that weakens a hold: a dropped
hold is kept and reported, and a taint added on one branch stops the other
branch's promotion of that run from landing.

## Applying a merge

```
tine merge-history apply --base BASE.json --theirs THEIRS.json --key KEY \
    [--target REF | --subject RUN] [--theirs-state DIR] [--theirs-lineage DIR]
```

`apply` refuses (exit 1, nothing written) while there is any conflict.
Otherwise it lands the merge as ordinary ref updates plus one signed record:

- **Refs** move in one compare-and-swap transaction from this repository's own
  values. The objects they name must already be here (`tine fetch` or a bundle
  first).
- **Merge queue.** A ref that a merge queue owns (`coord/merge-queue/ID` with
  that target) is not moved directly: its new run is enqueued, and the queue
  lands it under its gates and fencing as usual.
- **Labels** take the other side's label state file from `--theirs-state`;
  each decision row must hash to what the merged snapshot names.
- **Lineage records** are copied from `--theirs-lineage`; each file must hash
  to the merged snapshot's digest and verify as a signed record.
- **Holds** are only ever added.
- **The record.** An `attestation` (tine-attest/2, Ed25519) whose claim
  follows `opentine.history-merge/1`, targeting the run `--subject` names (or
  the merged value of `--target`):

  ```json
  {"convention": "opentine.history-merge/1",
   "base": "sha256:…", "sides": ["sha256:…", "sha256:…"], "merged": "sha256:…",
   "conflicts": [], "target": "heads/main"}
  ```

  It is stored and held under `history-merge:<merged digest>`; `tine hold
  release` refuses that row, so a loop cannot delete the record.

Every file is checked before anything is written. No object kind, wire
format or `tine verify` code is added: the merge is ref updates plus an
attestation under a claim convention.

## Verifying a merge

```
tine merge-history verify RECORD --base BASE.json --ours OURS.json --theirs THEIRS.json \
    [--public-key HEX]
```

`verify` re-runs the merge from the three snapshots and checks that the
claim's digests and conflicts match and that the signature verifies (under
`--public-key`, else the embedded key as `verified-tofu`). Which snapshot is
called "ours" does not matter. Signer trust comes only from the owner-pinned
trust bundle (SPEC 4.19, pinned key roles): when roles are pinned, the signer
must hold the `policy` role and must not hold the `optimizer` role
(`signer_trusted`); with no pinned bundle the output says `signers:
unpinned`.

`apply` checks the signing key before anything moves: a key listed as
`optimizer` (pinned, or in the unpinned `.tine/key-roles.toml`, which may still
refuse) never lands a merge, and when roles are pinned only a `policy` key does.
Snapshot label names must match `[a-z0-9][a-z0-9._-]{0,63}` and lineage ids
`sha256:HEX`, because both become file names when a merge lands.

The Python reference (`opentine/_history_merge_record.py`), the pyz
(`opentine/_pyz/_histmerge.py`) and the TS verifier
(`ts/verifier/src/histmerge.ts`) are three implementations of the same check.
They answer the shared fixture `tests/data/history_merge.json` (seeded merges,
every conflict kind, an edited claim, another key, an unsigned record and a
wrong snapshot) field for field. Like the lineage check, the fixture is outside
the frozen conformance vector families: `tine verify` gives the claim no
verdict (FREEZE.md, D1).

## JSON output

`--json` prints `tine-cli-merge-history/1` (`docs/schemas/tine-cli-merge-history-1.schema.json`).
The snapshot and the claim have schemas `opentine-history-snapshot-1` and
`opentine-history-merge-1`; both are conventions, not object kinds.

## Exit codes

`plan` exits 1 on a conflict; `apply` exits 1 on a conflict (nothing is
written) and refuses missing objects, label states or lineage records;
`verify` exits 1 when the record does not verify or the signer is not trusted.
