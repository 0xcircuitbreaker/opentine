# Self-modification lineage

A self-improving agent loop produces variants: a changed code tree, prompt,
config or set of weights, derived from one or more earlier variants by a
mutation run, kept or discarded by a selector, and sometimes promoted to a
label. OpenTine records each variant as a signed node with links to the
evidence for keeping it, so an auditor can ask of any variant: where did it
come from, and which signed evals justified each step?

This page covers the record, the check and the graph commands (0.59). Nothing here adds an object
kind, a predicate, a wire format or a conformance vector: a lineage record is an
existing `attestation` whose claim follows a documented convention, and the
check is a CLI command with its own codes (`tine verify` and the pyz are
unchanged).

## The record

`tine lineage record` signs an attestation on the mutation run with an Ed25519
key (`tine-attest/2`). Its claim:

```json
{
  "convention": "opentine.lineage.variant",
  "variant": "sha256:…",
  "artifacts": {"code_tree": "sha256:…", "prompt": "sha256:…",
                "config": "sha256:…", "weights": "sha256:…"},
  "parents": ["sha256:…"],
  "mutation_run": "run:sha256:…",
  "evals": [{"eval": "sha256:…", "verdicts_sha256": "…"}],
  "selector": "tournament",
  "decision": {"sha256": "…"},
  "policy": "…",
  "loop": "opt"
}
```

| Field | Meaning |
| --- | --- |
| `artifacts` | One or more of `code_tree`, `prompt`, `config`, `weights`, each a `sha256:` digest. Weights are named by digest only; OpenTine never stores them. |
| `variant` | `sha256:` over `opentine.lineage.variant.v1:` + JCS of `artifacts`. Equal artifacts are the same variant. |
| `parents` | Zero (a root), one, or many variant ids (a merge or recombination in an archive with many live variants). |
| `mutation_run` | The run that produced the variant; also the attestation's `target_id`. |
| `evals` | The `tine eval run` evals that justified keeping it, by eval id and the SHA-256 of their `verdicts.jsonl`. |
| `selector` | Free text: what chose this variant (a tournament, best-of-archive, a human). |
| `decision` | The SHA-256 of the `decision.json` that `tine promote` wrote (0.57), or `null`. |
| `policy` | The promotion policy's `policy_sha256` (taken from the decision when not given), or `null`. |
| `loop` | The loop id. Recording refuses when `tine loop stop` has stopped that loop. |

The record goes into a lineage folder, `REPO/.tine/lineage` by default, named
by digest with the evidence it cites:

```
variants/HEX.json     the signed record (HEX is the variant id's hex)
evals/HEX.jsonl       each justifying eval's verdicts, byte for byte
decisions/HEX.json    each cited promotion decision, byte for byte
```

The folder is not trusted for being there: the check re-hashes every file and
re-checks every signature, so a copy of the folder checks the same anywhere.
A record, decision or verdict with a duplicate JSON key is refused rather than
read last-wins, so two readers cannot see two different claims. Signatures are
checked against the key each document embeds: the check proves who signed,
not that the signer is trusted. A loop that holds its own eval key can still
sign its own verdicts; pin the eval and promotion keys (0.57 promotion pins)
and require a decision when that matters.

```
tine lineage record --run run:sha256:… --key optimizer.key \
    --code-tree sha256:… --prompt sha256:… \
    --parent sha256:… --eval evals/cand --decision promote/decision.json \
    --selector tournament --loop opt
```

Recording refuses an eval folder that does not verify. A record names its
evidence; it does not certify it, so the check runs again on every read.

## The check

`tine lineage check VARIANT` walks `parents` depth first from VARIANT, checks
every reachable record once, and exits 1 when it finds anything:

| Code | When |
| --- | --- |
| `lineage.variant-unknown` | VARIANT has no record |
| `lineage.record-invalid` | A record is malformed, is not Ed25519-signed by its `signer` (the embedded key's fingerprint), has an id that is not the digest of its artifacts, or targets another run |
| `lineage.parent-missing` | A parent has no record |
| `lineage.cycle` | The ancestry comes back to a variant on the current path |
| `lineage.evidence-missing` | A justifying eval is absent, its verdicts do not hash to `verdicts_sha256`, a verdict is unsigned, does not verify, repeats an item or scores another run than the mutation run (an eval of another variant cannot justify this one), or a variant with parents names no eval |
| `lineage.decision-mismatch` | The cited decision is absent or unsigned, is not an `opentine.promotion-decision/1` promote of the mutation run, was made under another policy than the record names, or cites none of the variant's evals among its `inputs` |

Each finding names the variant it is about, so a problem in an ancestor shows
up when checking any of its descendants. `--json` prints `tine-cli-lineage/1`:
`ancestors` in walk order and `findings` sorted by variant, then code.

## Links to promotion and loops

* **Promotion decisions.** A decision from `tine promote` (0.57) lists the eval
  folders, approvals, signed comparisons and the signed policy attestation it
  relied on as `inputs`. A variant citing it must share at least one eval with
  those inputs, and its mutation run must be the promoted candidate.
* **Policies.** `policy` is the `policy_sha256` that the decision records. The
  signed policy attestation (`opentine.promotion-policy/1`) is reached through
  the decision.
* **Loop stops.** A record names its loop, and `tine lineage record --loop`
  refuses to add a variant to a loop that `tine loop stop` has stopped.

## Python and TypeScript

`opentine._lineage_check.check` and the TS verifier's `checkLineage`
(`ts/verifier/src/lineage.ts`) take the folder as a map from relative path to
bytes. Both answer `tests/data/lineage_check.json` (the folder in base64 and
the `(code, variant)` pairs each case must report). The fixture is
regenerated with `python -m tests.test_059_lineage_fixture DIR`, and
`tests/test_059_lineage_fixture.py` fails when it is stale. It sits outside the
frozen conformance vector family.

## The graph, `why` and the archive

`tine lineage graph|why|archive|index` read a derived index of the same folder,
`LINEAGE_FOLDER/index/lineage.sqlite`. It reads the one claim above; there is
no second schema. The index is rebuildable and never authoritative: it is
rebuilt when missing or stale (its `source` is a digest of every folder file's
path and SHA-256, so any added, removed or edited record, eval or decision
makes it stale), deleting and rebuilding it gives an identical `graph_sha256`,
and `index --rebuild` forces a rebuild. A record filed under a name other than
its variant id is not indexed.

* `graph [--format dot|json] [--loop LOOP]` lists variants, parent edges,
  `missing_parents` and `cyclic` (variants on or behind a parent cycle).
  `signed` means the record is Ed25519-signed by its `signer` and verifies,
  the same test the check applies: a copied signature block does not count.
* `why VARIANT [--max-depth N] [--max-nodes N]` walks the variant to every
  ancestor and its evidence: artifacts, mutation run, evals, the dataset,
  scorer or judge and signer of their filed verdicts, the selector, the policy,
  the loop, the promotion decision and the decision's `inputs` (approvers,
  signed policy, comparisons). It touches one variant, one edge and one
  evidence query per ancestor (`visited` counts them). It does not trust the
  index: every ancestor it reports is re-derived from its record in the folder,
  and a mismatch (a hand-edited index) rebuilds the index once and walks again
  (`"rebuilt": true`). It then runs `tine lineage check` over the folder and
  carries its `ok` and `findings`; it exits 1 when the check refuses, so `why`
  never presents a laundered ancestry as justified. `--max-nodes` (default
  10000) caps the walk and sets `truncated`.
* `archive [--loop LOOP] [--signed]` summarises a population with many
  variants and non-linear parents: per-variant fan-in and fan-out and totals.
* `index [--rebuild]` builds the index and prints its path and hash.

`--json` prints `tine-cli-lineage/1` for every subcommand.

## Not yet

The Tineyard view of the graph comes later. A trust pin for record and eval
signers (the check proves who signed, not that the signer is trusted), and a
limit on lineage folder size, are open.
