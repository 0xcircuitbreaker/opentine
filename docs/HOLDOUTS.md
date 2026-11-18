# Sealed holdouts, canaries and exposure budgets (0.61)

A holdout only measures generalization while the system being measured has
not seen it. In a self-improving agent loop the optimizer can read the
repository, so a holdout kept in clear next to the code is one `cat` away from
becoming training data. OpenTine 0.61 keeps holdouts sealed, records every
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
| `eval`    | unseal items (0.61, new optional role)        |

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
 "items": 120, "generation": 1, "previous": null,
 "previous_commitment_sha256": null,
 "budget": {"max_unseals": 3, "max_items": 50}}
```

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
paraphrase that changes most of the words; an embedding near-duplicate check
is planned once a pinned embedding model exists.

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
advisory. The lengths file is not signed; the check is only as good as the
scoring run that produced it.

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

- Exposure counts live in the holdout folder. A record removed from the end
  of the chain is not detectable from the folder alone; keep the folder under
  the repository's retention and holds, and rotate after an incident.
- `eval.holdout-touched` reads a run's recorded steps and prompt. Content a
  run used without recording it is not seen.
- The canary check depends on the code lengths the scoring run reports.
