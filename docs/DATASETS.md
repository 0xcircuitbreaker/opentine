# Curated dataset versions

*0.75.* `tine dataset curate` turns recorded runs into a signed **dataset
version**: a list of member runs chosen by a selection expression, deduplicated
by content, with every tainted run left out unless a pinned key justified it.
Every record below is an attestation (an existing object kind) whose claim
names its convention. No object kind and no `tine verify` code is added
([FREEZE.md](FREEZE.md)); `tine verify` gives these claims no verdict, and the
checks live in `tine dataset verify-version`, `tine dataset versions` and the
TS verifier.

## Curating a version

```text
tine dataset curate --select 'failures:EVAL' --out train --key curator.key --repo .
```

1. **Select.** The expression is terms joined by `and`; any term may start with
   `not`:

   | Term | Runs |
   | --- | --- |
   | `all` | every run |
   | `failures:EVAL` | a signed eval verdict of `EVAL` that did not pass |
   | `passes:EVAL` | a signed eval verdict of `EVAL` that passed |
   | `eval:EVAL` | any signed eval verdict of `EVAL` |
   | `model:GLOB` | `model_info` matches `GLOB` |
   | `run:RUN` | that one run |

   `failures of eval EVAL` is read as `failures:EVAL`. Verdicts come from the
   lineage `evals/*.jsonl` files, the folders `tine query index --evals`
   remembered, and each `--evals DIR`'s `verdicts.jsonl`. A verdict whose
   signature does not verify is ignored. Record anchor runs (`model_info`
   starting `opentine/`) are never candidates.
2. **Withdrawals.** Runs with a held, signed withdrawal are left out and listed
   in `withdrawn`.
3. **Taint filter.** Runs named by any of these five sources are left out and
   listed in `taint_filter.excluded`:

   | Source | What taints a run |
   | --- | --- |
   | `integrity-taint` | a held integrity taint ([INTEGRITY.md](INTEGRITY.md)) |
   | `monitor-verdict` | a held monitor verdict on the run that was not `allow`, or was enforced ([MONITORS.md](MONITORS.md)) |
   | `oversight-reject` | a held oversight `reject` whose item names the run ([OVERSIGHT.md](OVERSIGHT.md)) |
   | `sabotage-task` | a held sabotage task record on the run whose side task was attempted or achieved ([SABOTAGE.md](SABOTAGE.md)) |
   | `transcript-flag` | a **verified** behaviour flag naming the run as evidence ([TRANSCRIPT_FLAGS.md](TRANSCRIPT_FLAGS.md)) |

   The filter reads only held records, which `tine hold release` refuses, so
   a loop cannot un-taint its own trajectories by deleting a file. It fails
   closed: an unreadable holds file, or a held record that cannot be read,
   stops curation.

   Taint follows content: a candidate whose FastCDC chunks (the dedup
   parameters below) overlap the chunks of a tainted run by at least half of
   its own chunks is left out too and listed in `excluded`, so a renamed or
   lightly edited copy of a tainted trajectory does not get in. A
   justification that names the copy lets it in like any tainted run.
4. **Dedup.** Each remaining run's redacted transcript text (the text `tine
   transcripts` analyses, with the run's own id removed) is cut into FastCDC
   chunks with fixed parameters (`fastcdc-gear49`, min 64, average 256, max
   2048 bytes). The content digest is SHA-256 over the chunk digests. Runs with
   the same content keep the smallest run id; the others are listed in
   `dedup.dropped` with the member they repeat.
5. **Sign.** The claim is signed onto a small anchor run and held by a
   `dataset-record:version:NAME:N` row. Version numbers follow the last held
   version of the same name that is `verified` (or, with no pinned curator
   role, that the same key signed); `previous` names it. A version another
   key signed, an optimizer's included, never sets the next number.

### Including tainted runs

Tainted runs come in only with `--include-tainted --justification ID`, where
`ID` is an `opentine.dataset-justification/1` attestation for the same dataset
name, signed by a pinned `curator` or `policy` key that is not an optimizer key:

```text
tine dataset justify train --run RUN --reason 'negative examples for a monitor' --key policy.key
tine dataset curate --select all --out train --include-tainted --justification ID --key curator.key
```

Only the tainted runs the justification names come in; they are listed in
`taint_filter.included_tainted`, and the version records the justification id.
Without a pinned trust bundle, or with an optimizer, unpinned, forged or other
dataset's justification, curation refuses (fail closed).

## Keys

The signer of every record is the key that signed it (`used_key_fingerprint`).
Roles come only from the owner-pinned trust bundle
([key roles](CLI.md)). An optimizer key may not curate, justify or write a
tombstone, and an unreadable key-role policy refuses. A version is `verified`
by `tine dataset versions` only when its offline check holds and its curator is
a pinned `curator` key, and no member that the version did not justify is
tainted now (a flag or taint recorded after curation turns it `unverified: N
member(s) tainted since curation`); with unpinned roles it is listed `unverified: ...`
(advisory, D12).

## Claim conventions

### `opentine.dataset-version/1`

```json
{"convention": "opentine.dataset-version/1", "name": "train", "version": 1,
 "previous": null, "selection": "failures:sha256:...",
 "members": [{"run": "run:sha256:...", "content": "sha256:..."}],
 "members_digest": "sha256:...",
 "dedup": {"chunking": {"scheme": "fastcdc-gear49", "min": 64, "avg": 256, "max": 2048},
           "candidates": 4, "dropped": [{"run": "run:sha256:...", "same_as": "run:sha256:..."}]},
 "taint_filter": {"mode": "default", "sources": ["integrity-taint", "monitor-verdict",
                  "oversight-reject", "sabotage-task", "transcript-flag"],
                  "excluded": ["run:sha256:..."], "included_tainted": [], "justification": null},
 "withdrawn": [], "curator": "sha256:<fingerprint>", "created_at": "2026-11-21T00:00:00Z"}
```

Schema: [`opentine-dataset-version-1`](schemas/opentine-dataset-version-1.schema.json).
The **offline check** needs only the attestation payload:

* the exact set of fields; `name` lower-case letters, digits, `.`, `_`, `-`;
  `version` 1 with `previous` null, or later with `previous` an attestation id;
* `members` sorted by run, each run once, no two sharing `content`;
  `members_digest` is `sha256:` over the canonical JSON of `members`;
* dropped runs sorted, distinct, not members, each `same_as` a member;
  `candidates` at least members plus dropped; the chunking parameters above;
* excluded and withdrawn runs sorted, distinct, not members; the five sources
  in order; `default` has no included runs and no justification;
  `include-tainted` names its justification and includes only members;
* the attestation targets a run; the Ed25519 signature holds under the
  embedded key, that key is the payload `signer` and the claim's `curator`.

`tine dataset verify-version` runs it in Python and `checkDatasetVersion` in
`ts/verifier/src/datasetversion.ts` in TS; both answer the shared vectors in
`tests/data/dataset_version.json` (regenerated by `tests/dataset_vectors.py`)
field for field.

### `opentine.dataset-justification/1`

`{"convention", "dataset", "runs" (sorted, at least one), "reason", "curator", "at"}`,
signed onto the first run and held as `dataset-record:justification:NAME:RUN`.

### `opentine.dataset-withdrawal/1`

`{"convention", "run", "reason", "contributor", "at"}`, signed onto the run and
held as `dataset-record:withdrawal:RUN`. It counts when its signature holds,
`contributor` is the key that signed, and that key is not a pinned `optimizer`
key (`withdraw` refuses one). A withdrawal only ever removes a run.

`tine dataset withdraw` writes the contributor convention
`opentine-dataset/withdraw/1` (docs/DATASET_CONTRIBUTORS.md, held as
`dataset-withdraw:RUN`). Curation counts it the same way when its state is
`verified` and the contributor is not a pinned `optimizer` key, so a
contributor's withdrawal removes the run from every later version and the next
version writes a tombstone. `opentine.dataset-withdrawal/1` stays readable for
records written through the Python API.

### `opentine.dataset-tombstone/1`

`{"convention", "dataset", "version", "run", "withdrawal", "curator", "at"}`:
written by `curate` for each run the previous version held and a withdrawal now
removes, held as `dataset-record:tombstone:NAME:RUN`.

## Querying

`tine query` indexes `dataset_versions` and `dataset_members`
([QUERY.md](QUERY.md)); `--verify` re-derives each row from its attestation and
reports `verified` only for a pinned `curator` signer without `optimizer`.

```text
tine query "SELECT name, version, members, excluded FROM dataset_versions" --verify
tine query "SELECT m.run, r.model FROM dataset_members m JOIN runs r ON r.oid = m.run"
```

## Contributing runs to an open run dataset

A project that publishes a dataset from contributed runs can use the same
records:

* **Before contributing**, run `tine redact` and `tine bundle create
  --redacted-public` so only redacted text leaves the machine; the curated
  content digest is computed from redacted text too.
* **Check what a version holds**: `tine dataset versions NAME --json` lists every
  version, and `tine query "SELECT run FROM dataset_members WHERE oid = 'ID'"`
  lists its members, so a contributor can see whether a run is in.
* **Withdraw** a run with `tine dataset withdraw RUN --key KEY --reason
  consent-withdrawn|privacy|licence|quality|other` (docs/DATASET_CONTRIBUTORS.md).
  Every later version leaves it out and lists it in `withdrawn`, and the first
  version after the withdrawal writes a tombstone naming the version that held
  it. Published versions are not rewritten: a withdrawal applies forward.
* **Use a version in evals and holdouts** with `tine dataset materialize ID --out
  D.jsonl`: only a `verified` version is written (a pinned `curator` signer, no
  member tainted since curation), as eval items `tine eval` scores and
  `tine dataset seal` seals; runs withdrawn since curation are left out and
  listed. Tombstones are queryable as `dataset_tombstones` (docs/QUERY.md).
* **Verify a published version offline** with `tine dataset verify-version
  --file PAYLOAD.json` or the TS verifier; neither needs the repository or the
  network.

Contributed text must not carry personal names, emails or other private
details; the redaction step above is the place to remove them.
