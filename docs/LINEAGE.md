# Self-modification lineage

A self-improving agent loop produces variants: a changed code tree, prompt,
config or set of weights, derived from one or more earlier variants by a
mutation run, kept or discarded by a selector, and sometimes promoted to a
label. OpenTine records each variant as a signed node with links to the
evidence for keeping it, so an auditor can ask of any variant: where did it
come from, and which signed evals justified each step?

This page covers the record, the check and the graph commands (0.58). Nothing here adds an object
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
| `artifacts` | One or more of `code_tree`, `prompt`, `config`, `weights` and (0.88) `skill`, each a `sha256:` digest. Weights are named by digest only; OpenTine never stores them. `skill` names a skill tree; `tine lineage diff PATH --tree` prints the digest to record. |
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
| `lineage.signer-untrusted` | Eval signers are pinned (below) and a justifying verdict is signed by a key that is not an allowed eval signer, or by an optimizer key |

Each finding names the variant it is about, so a problem in an ancestor shows
up when checking any of its descendants. `--json` prints `tine-cli-lineage/1`:
`ancestors` in walk order and `findings` sorted by variant, then code.

### Signer trust

A signature proves who signed a verdict, not that the signer may judge the
loop: a loop could sign its own evals and record a variant on them. `check`
and `why` therefore pin eval signers with the 0.57 key separation:

* the `scorer` role of `REPO/.tine/key-roles.toml` names the allowed eval
  signers, and its `optimizer` role the loop's own keys;
* `--promotion-policy TOML` adds the `eval_signers` of a `tine promote`
  policy; with both, a signer must be in both.

Every verdict of every justifying eval must then be signed by an allowed key
that is not an optimizer key (an optimizer key listed as a scorer is still
refused), or the variant gets `lineage.signer-untrusted`. The output says
`"signers": "pinned"`. With neither source the output says
`"signers": "unpinned"` and the text output prints a warning: the check then
proves who signed, and makes no claim that the signer is trusted.

### Size limit

Every lineage command except `record` lists and sizes the folder before reading
it and refuses (exit 1, `lineage.too-large`) one over 200000 files or 1 GiB
(`--max-files N`, `--max-bytes N`), without reading a file.

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

## Tainted scores (0.60)

A variant whose mutation run carries a signed `opentine.integrity.taint`
(`tine integrity check RUN --key KEY`, docs/INTEGRITY.md) is reported by
`check` and `why` as `lineage.score-tainted`, and the command exits 1: a score
from a run that modified a protected surface cannot justify a lineage step.
The taint is read from `REPO/.tine/integrity/taints/`; the lineage folder and
the TS `checkLineage` fixture are unchanged.

## Trends

`tine trends` (0.72) reads the same folder and reports per-generation metrics,
regressions against parents and tainted or quarantined inputs, with an export a
browser recomputes byte for byte. See docs/TRENDS.md.

From 0.72 `tine lineage record` refuses to re-sign a variant that already has a
record with a different claim (other parents, evals or run): records are
append-only, so a loop cannot re-root a regressed variant to drop its parent.

## Structural diff (0.88)

`tine lineage diff OLD NEW` compares two variant trees (a directory or one file
each) file by file. A file is unchanged only when its bytes are; every other
file is listed with both SHA-256 digests, a kind, whether its structure changed
(`structural`) and the changes:

| Kind | Compared as |
| --- | --- |
| `python` | AST symbols: each function and class by qualified name, a class header, every other statement by digest. A changed default, decorator or constant is a `changed` symbol; comments and formatting are not structural. A source that does not parse falls back to tokens. |
| `prompt` | Markdown and text (`.md`, `.txt`, `.prompt`, names with `prompt`) split into sections by heading path (`Role / Rules`); added, removed, changed and reordered sections. |
| `tools` | A whole `tools/list` result (`{"tools": [...]}`, its JSON-RPC envelope, or a bare list of definitions with `inputSchema`, `input_schema` or `parameters`): tools by name and `tool_def_digest` (the same digest `tine mcp-proxy` records on each `tools/call`; see `docs/SCAFFOLD.md`), so a schema change under a kept name and description is `changed`. A file with other top-level keys is a config. |
| `config` | JSON, TOML and YAML (YAML only when PyYAML is installed) as leaves by path; reordered keys are not a change, a value that changes type is. A repeated key refuses the whole diff (`lineage-diff.duplicate-key`). |
| `text` | Any other UTF-8 file, as a whitespace-insensitive token diff. |
| `binary` | Digests only (also a symbolic link, recorded by its target, never followed). |

Every changed file also carries hidden-edit `flags`, so an edit made to look
like no change is named: `invisible` (a zero-width or other format character
was added), `bidi` (a bidirectional control), `non-ascii` (a non-ASCII letter,
a possible look-alike), `nfkc` (equal after NFKC normalisation, which Python
applies to identifiers), `line-endings` and `whitespace`.

With `--key` the diff is signed as an existing `attestation` payload
(`tine-attest/2`, Ed25519) and filed in `LINEAGE_FOLDER/diffs/HEX.json` (or
`--out`). Its claim follows the `opentine.lineage.diff` convention:

```json
{"convention": "opentine.lineage.diff",
 "from": {"tree": "sha256:…", "variant": "sha256:…" | null, "bound": true | false | null},
 "to":   {"tree": "sha256:…", "variant": "sha256:…" | null, "bound": true | false | null},
 "totals": {"files": 7, "changed": 2, "structural": 1, "flagged": 1},
 "files": [{"path", "before", "after", "status", "kind", "structural", "changes", "flags"}]}
```

`tree` is `sha256:` over `opentine.lineage.diff.tree.v1:` + JCS of
`{path: sha256 hex}`. `--from`/`--to` name variants that must be signed records
in the lineage folder; `bound` says whether the variant's recorded artifacts
include the tree's digest. The `target_id` is the newer variant id, else the
newer tree's digest. `tine lineage diff --check FILE [OLD NEW]` verifies the
signature (the signer must be the signing key) and, given both trees,
recomputes the claim, `bound` included (read from the lineage folder, never
taken from the signed file): exit 1 with `lineage-diff.bad-signature` or
`lineage-diff.mismatch`. Without the trees only the signature is checked and
the result's `bound` is `unverified` (`recomputed` with them); with `--policy
FILE` under `profile = "rsi"` that is refused (`lineage-diff.mismatch`). The
diff is evidence: it does not block a promotion.

No folder is skipped (a cache or VCS folder can hold scaffold). A Python file
with a coding cookie other than UTF-8 is diffed by tokens, since Python would
decode its bytes differently. A config key that is not plain
(`[A-Za-z0-9_-]+`) or not a string is quoted in its path, so `{"a.b": 1}` is not
`{"a": {"b": 1}}`. In `tine promote`, signed records of one run that name
different skills are a skill change, and under `skill_labels = "required"` a
`skill.*` label cannot move to such a candidate. Under that rule a record
counts only when its signer holds a pinned role of the repository's key-role
policy (else of the lineage folder's `.tine`) and is not an `optimizer` key; a
record another key signed makes its run's skill unknown, refused like
conflicting records.

## Not yet

The Tineyard view of the graph comes later. Record signers are proven, not
pinned to a role, except for skill labels under `skill_labels = "required"`.
