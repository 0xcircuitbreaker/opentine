# Sealed holdouts, canaries and exposure budgets (0.60)

A holdout only measures generalization while the system being measured has
not seen it. In a self-improving agent loop the optimizer can read the
repository, so a holdout kept in clear next to the code is one `cat` away from
becoming training data. OpenTine 0.60 keeps holdouts sealed, records every
access, limits how much of a holdout may be revealed, and refuses evals and
promotions that the custody record does not support.

Nothing here adds an object kind, a wire format or a `tine verify` code. The
items are sealed with the existing `TINEAES3` envelope; the commitment, the
access records and the canary registrations are existing attestations whose
claims follow the conventions below. Refusals belong to the new commands
(`holdout.*`, `canary.*`) and to `promote.*` and `eval.*`.

## Key roles

Two roles from the owner-pinned trust bundle (0.59, `tine trust bundle create
--key-roles`) gate the commands:

| role      | may                                           |
|-----------|-----------------------------------------------|
| `dataset` | seal a holdout, register canaries             |
| `eval`    | unseal items (0.60, new optional role)        |

A key in the `optimizer` role never qualifies, and roles that only appear in an
unsigned `.tine/key-roles.toml` grant nothing: the command refuses with
`holdout.role`. `tine keys lint` reports an optimizer key that also holds the
`eval` role as a `fail:` finding, like the other guarded roles.

## Sealing

```
tine dataset seal items.jsonl --out .tine/holdouts/h1 --name h1 \
    --max-unseals 3 --max-items 50 --key dataset.key --seal-key ~/secrets/h1.key
```

The folder holds:

| path                     | contents                                                 |
|--------------------------|----------------------------------------------------------|
| `commitment.json`        | signed claim `opentine.holdout.commitment/1`             |
| `leaves.json`            | salted leaf hashes in item order                         |
| `items/NNNNNN.sealed`    | one `TINEAES3` ciphertext per item                       |
| `access/NNNNNN.json`     | signed access records, chained                           |
| `canaries/*.json`        | signed canary registrations                              |

A leaf is `sha256("opentine.holdout.leaf.v1\0" || salt || JCS(item))` with a
random 16-byte salt per item, so a leaf does not let anyone confirm a guessed
short answer. The root is the RFC 6962 Merkle tree hash over the leaves. Each
ciphertext authenticates purpose `holdout-item`, the holdout name and the
context `ROOT:INDEX`, so a ciphertext moved to another slot does not open.

The seal key is a 32-byte file; `seal` creates it (mode 0600) when it does not
exist and refuses one inside the holdout folder. Keep it out of the repository.

The commitment claim:

```json
{"schema": "opentine.holdout.commitment/1", "holdout": "h1", "root": "<hex>",
 "dataset": "sha256:<hex>", "items": 120, "generation": 1, "previous": null,
 "previous_commitment_sha256": null,
 "budget": {"max_unseals": 3, "max_items": 50}}
```

`dataset` (0.76) is the items' dataset digest, the same digest `tine eval`
puts on each verdict. The policy input marks an eval as a holdout eval when its
`dataset` equals it (see docs/POLICY.md). A commitment sealed before 0.76 has
no `dataset` and matches no eval; reseal it (`--rotate-from`) to use it.

## Unsealing and access records

```
tine dataset unseal .tine/holdouts/h1 --out /tmp/h1.jsonl --run RUN \
    --why "candidate eval for prod" --purpose eval --key eval.key --seal-key ~/secrets/h1.key
```

Before it decrypts anything, `unseal` writes an access record:

```json
{"schema": "opentine.holdout.access/1", "holdout": "h1", "root": "<hex>",
 "sequence": 0, "previous": null, "run": "run:sha256:...", "why": "...",
 "purpose": "eval", "items": [0, 1, 2], "over_budget": false}
```

The signer is who; `run` is which run; `why` is why. `previous` is the sha256
of the previous record's bytes, so the records form a chain and a removed
record is visible. Each released item is checked against its committed leaf.

## Exposure budgets

The exposure of a holdout is the number of valid access records (`unseals`)
and the number of distinct items they revealed (`revealed`). `unseal` refuses
with `holdout.budget-exceeded` when the next unseal would go past either
budget. `--exceed-budget` performs the unseal anyway and records
`"over_budget": true`; from then on the holdout is exposed.

Every access record is also stored as a `blob` object and held (a `tine hold`
row whose target starts with `holdout-access:ROOT:`), and `tine hold release`
refuses those rows, as it does for 0.57 loop stops and 0.59 taints. Exposure is
computed from the union of the folder's records and the held copies, so
deleting `access/` (or one record) lowers nothing. An unreadable holds file
refuses (`holdout.holds`). A record that is not validly signed by an allowed
`eval` key is ignored, including when `unseal` picks the next sequence: a
forged `NNNNNN.json` in the next slot is replaced, not obeyed. Two validly
signed records that claim one sequence break the chain (fail closed).

`tine dataset exposure DIR --json` reports the counts, the records and the
chain. `tine promote ... --sealed-holdout DIR` (repeatable) refuses with
`promote.holdout-exposed` when a named holdout is over budget or its access
records do not chain. The budget is read from the commitment, so `exposure`,
`unseal` and promote require the commitment to be signed by a `dataset`-role
key in the owner-pinned key roles: a commitment re-signed by any other key
(for example to raise the budget) is refused with `holdout.role`, and promote
reports it as `promote.holdout-exposed`. A holdout that has been exposed is replaced by rotation,
not by deleting records.

## Rotation

```
tine dataset seal fresh.jsonl --out .tine/holdouts/h2 --name h2 --rotate-from .tine/holdouts/h1 ...
tine dataset exposure .tine/holdouts/h2 --chain .tine/holdouts/h1 --json
```

A rotated generation names the old root (`previous`) and the sha256 of the
old commitment's bytes (`previous_commitment_sha256`), and its `generation`
is one more. `exposure --chain OLDER...` (oldest first) checks every link and
refuses with `holdout.chain` when one does not name the commitment before it.

## Evals refuse touched runs

```
tine eval run /tmp/h1.jsonl --outputs outs.jsonl --scorer exact --key eval.key \
    --out evals/h1 --holdout .tine/holdouts/h1 --repo .
```

With `--holdout`, `eval run` reads every scored run (the runs named by the
outputs, the items and `--run`) from the repository and refuses with
`eval.holdout-touched`, signing nothing, when:

- a non-eval access record (`--purpose other`) unsealed items for that run;
- an item's `input` or `expected` (16 characters or more) is in the run's
  recorded content in clear; or
- the 5-word shingles of an item's text are contained in the run at a ratio of
  0.8 or more (a paraphrase that keeps most of the wording). The threshold is
  printed in the refusal.

Shingle containment catches near-verbatim reuse. It does not catch a
paraphrase that changes most of the words. From 0.74, `tine dataset
contamination --embedding-threshold COSINE` adds an embedding near-duplicate
check (docs/INTEGRITY.md, docs/TRANSCRIPT_FLAGS.md).

## Query accounting (0.86)

Exposure budgets count unseals and revealed items. An eval that scores a
holdout also reveals something (how many items passed, the mean score), and a
loop that keeps scoring variants against the same holdout and keeps the best
one is selecting on the holdout. So every eval against a sealed holdout is
counted as a query.

```
tine dataset seal items.jsonl --out .tine/holdouts/h1 --name h1 \
    --max-unseals 3 --max-items 50 --max-queries 20 --key dataset.key --seal-key ~/h1.key
tine eval run /tmp/h1.jsonl --outputs outs.jsonl --scorer exact --key eval.key \
    --out evals/v7 --holdout .tine/holdouts/h1 --lineage gen-4 --repo .
```

After `eval run` signs an eval, it writes one query record per sealed holdout
the eval scored: the folder named with `--holdout`, and every folder under
`.tine/holdouts/` whose commitment `dataset` equals the eval's dataset digest
(so leaving out `--holdout` does not skip the count when all items were
unsealed). The record is signed with the eval key, stored as
`DIR/queries/HEX.json` and kept as a held blob (target
`holdout-query:ROOT:HEX`) that `tine hold release` refuses:

```json
{"schema": "opentine.holdout.query/1", "holdout": "h1", "root": "<hex>",
 "lineage": "gen-4", "eval": "sha256:<eval id>", "verdicts_sha256": "<hex>",
 "dataset": "sha256:<hex>", "revealed": {"items": 50, "passed": 41, "mean_score": "0.82"},
 "count": 21, "max_queries": 20, "over_budget": true}
```

`count` is the number of distinct evals recorded for that lineage node on that
holdout, this one included (`--lineage`, default `unattributed`).
`max_queries` comes from the signed commitment (`--max-queries`); a commitment
without it has no query budget and never flags. Counts are the union of the
folder's files and the held copies, so deleting a file lowers nothing; a
record whose signature does not verify (signer bound to the signing key) does
not count.

Where the count shows up:

- `tine eval run --json` lists the records it wrote under `holdout_queries`.
- `tine dataset exposure --json` adds `queries`: `max_queries`, `total`,
  `lineages` (count per node) and `over_budget` (the nodes past the budget).
  `ok` does not change.
- `tine trends --json` flags a variant `holdout.query-over-budget` when an
  eval it cites has an over-budget query record (or the holds cannot be read),
  and `tine query` shows the same flag in `trend_points.flags`.
- `tine promote` reports a holdout on which any lineage node is over budget.
  By default this is the advisory `advisory:holdout.query-budget` (D12). With
  `holdout_queries = "required"` in the signed `[promote]` policy, or
  `profile = "rsi"` (which requires it), promote refuses with
  `promote.holdout-query-budget`. Rotate the holdout (`--rotate-from`) to
  continue.

This is counting only: an eval's result is not perturbed, and no noise is
added to what a query reveals.

## Canaries

Canaries are registered in the repository, not in the holdout folder, with
`tine dataset canary-add TEXT --entropy-bits N --holdout NAME --key KEY` (claim
convention `opentine.integrity.canary`; it counts only for a pinned
`dataset`-role key that is not an optimizer key). `tine integrity scan` finds
them in runs, prompts, memory and exported packs, and `tine dataset
canary-check LENGTHS.json` refuses a model that codes a counted canary below its
declared entropy. See docs/INTEGRITY.md for the commands, the normalization
they apply and what a writer can still do.

`tine promote --canary-lengths FILE` runs the same check and refuses with
`promote.canary-failed` when it does not pass: a counted canary coded below its
entropy, a lengths file that scores no counted canary, or one that does not
parse (NaN, infinity, negative or non-numeric lengths). Advisory findings stay
advisory. The signed lengths must name the candidate being promoted as their
scoring run; lengths for any other run are refused with
`promote.canary-run-mismatch`, so a clean model's scores cannot vouch for it.

The lengths file is a signed attestation under the claim convention
`opentine.integrity.canary-lengths` (`{"convention", "run", "model",
"lengths": [{"canary_sha256", "code_millibits"}]}`, `target_id` the scoring run
id). `tine dataset canary-sign LENGTHS.json --run RUN --key KEY [--out FILE]`
writes one from an unsigned `{"model", "lengths": [{"canary_sha256",
"code_bits"}]}` file (lengths rounded down to millibits; `--json` prints
`tine-cli-canary/1` with `run`, `signer`, `canaries`, `out` and `sha256`). Its signer must hold the
`scorer` role, and not the `optimizer` role, in the owner-pinned key roles;
`canary-check --run RUN` also requires it to name that run. An unsigned,
unpinned or unbound file is refused with `canary.unsigned`.

Canary registrations are held like access records (`holdout-canary:HEX`), so
deleting a registration file does not stop the canary counting, and a file
whose bytes match none of its held copies is refused as `canary.tampered`.

The in-clear check of `eval.holdout-touched` compares item and run text after
NFKC normalization, casefolding, folding common Cyrillic and Greek lookalike
letters and dropping everything but letters and digits, so changing case,
whitespace or punctuation does not hide an item.

## What stays out of packs and bundles

The holdout folder holds only ciphertexts, salted hashes and signed claims.
Released items go to the `--out` path you give; nothing in `seal`, `unseal`,
or `exposure` writes an item into the object store. The
test `tests/test_061_holdout_leaks.py` seals a holdout inside a repository,
unseals it, packs and bundles the repository and scans every file, every
object, the pack and the unpacked bundle for each item's text; a control run
that does contain an item shows the scanner finds it.

## JSON output

All six commands print `tine-cli-holdout-1` with `--json`
(`docs/schemas/tine-cli-holdout-1.schema.json`). A refusal is `ok: false`
with `refusals: [{code, detail}]` and exit 1.

## Limits

- Query counts are per lineage node as the eval signer names it. A loop that
  signs its own evals can spread queries over many node names; the total per
  holdout is in `exposure` for that reason. An eval of a subset of a holdout,
  run without `--holdout`, has another dataset digest and is not matched.

- Held copies need a repository: a holdout used with no `--repo` counts only
  the records in its folder. A writer who can rewrite `.tine/holds` and the
  object store directly is outside this model, as for loop stops and taints.
- `eval.holdout-touched` reads a run's recorded steps and prompt. Content a
  run used without recording it is not seen.
- The canary check depends on the code lengths a pinned scorer signs; a
  scorer key in the optimizer's hands defeats it.
- Out of scope for 0.60: a canary split across several objects (each object
  is scanned on its own); real paraphrases of an item (word 5-gram containment
  and MinHash catch near copies only, until embeddings in 0.74); compressed
  packs passed to `integrity scan --file` as raw files (they are searched as
  stored bytes); and the full Unicode confusables table (only common Cyrillic
  and Greek lookalikes are folded).
