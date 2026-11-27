# Measuring-stick integrity: protected surfaces (0.60)

A self-improving agent loop is only as honest as the things that score it.
If a run can edit the grader, delete a failing test, loosen the sandbox or
read the holdout, its score measures the edit, not the agent. `tine integrity`
lets a repository name those measuring sticks, pin them by digest, and refuse
any score from a run that touched them.

## The protected list

`.tine/protected.toml` names each surface by kind, with globs and pinned
sha256 digests (hex over the file's bytes):

```toml
version = 1

[[surface]]
name = "graders"
kind = "grader"            # grader | test | holdout | sandbox | scorer
globs = ["evals/graders/**"]
[surface.pins]
"evals/graders/judge.py" = "<64 hex>"
```

Globs are repository-relative posix paths: `**` spans directories, `*` and
`?` stay inside one directory, every other character is literal. Paths in
the list and in findings always use `/`.

`tine integrity pin --repo PATH` writes the current digest of every file the
globs or pins cover into the list. It never signs: the list must then be
pinned again.

### The list itself is pinned

A loop that could edit the list could unprotect anything. So the list counts
only when `.tine/integrity/protected.json` is an existing `attestation`
(Ed25519) whose claim is

```json
{"schema": "opentine.integrity.protected/1", "protected_sha256": "<sha256 of the list's bytes>"}
```

signed by a `policy`-role key that is not also an `optimizer` key.
`tine integrity sign --key KEY` writes it. Any edit to the list's bytes, a
signature by another key, or no `policy` role at all is
`fail:protected-list-unsigned`; no list is `fail:protected-list-missing`.

The `policy` role counts only when it is *pinned* (0.59): it comes from an
owner-signed trust bundle (SPEC 8.26) whose `key_roles` carry it and whose
owner key is pinned outside the repository -- `$OPENTINE_TRUST_OWNER` or
`$XDG_CONFIG_HOME/opentine/trust-owner`; the bundle is
`$OPENTINE_TRUST_BUNDLE` or `.tine/trust-bundle.note`. A `policy` role named
only in the unsigned `.tine/key-roles.toml` is `roles: unpinned` and pins
nothing, so a loop that adds its own key there cannot re-sign the list. Sign
existing roles with `tine trust bundle create --key OWNER --name NAME
--serial N --pin FP --key-roles .tine/key-roles.toml --out
.tine/trust-bundle.note`; a bundle with a lower serial than the highest one
seen (kept in `$XDG_CONFIG_HOME/opentine/trust-bundle-serials.json`) is
refused, as in 0.51.

## `tine integrity check RUN`

`tine integrity check RUN [--repo PATH] [--strict] [--key KEY] [--record FILE]
[--json]` reads
the stored run's tool calls and judges them, and the current digest of every
pinned file, against the list:

- a file tool's path argument (`file_path`, `path`, `notebook_path`, ...) is a
  write, delete or read by the tool's name (`Write`, `Edit`, `Read`, ...);
- a shell tool's command is split for `rm`/`git rm`/`unlink` (delete),
  `>`/`>>`/`tee`/`sed -i` (write) and `cat`/`head`/`tail`/`less` (read);
- a shell tool also counts `cp`/`install`/`rsync` destinations, `mv`, `ln`,
  `truncate`, `touch`, `chmod`, `patch`, `dd of=`, `perl -i`, `git
  checkout|restore|mv|apply|reset|stash|am` targets and, for inline code
  (`python -c`, `perl -e`, `sh -c`, `$(...)`) that writes, every path-like
  token in it;
- a tool with an unknown name is a write or delete when its name says so
  (`fs_save_file`, `move_file`, `remove_path`); list-valued path arguments
  (`paths`, `files`) count;
- paths are normalized (`a/../b` is `b`), matched ASCII case-insensitively
  (`Evals/Graders/x.py` is `evals/graders/x.py` on Windows and macOS), and a
  symlink still on disk is resolved to the file it names; absolute paths are
  made relative to the repository; paths outside it are ignored;
- a write or delete of the trust root itself -- `.tine/protected.toml`,
  `.tine/key-roles.toml`, `.tine/trust-bundle.note` or anything under
  `.tine/integrity/` (the list's pin and the filed taints) -- is `fail:protected-surface-modified` on the
  `protected-list` surface whether or not the list names them;
- (0.85) a shell command that sets or unsets an `OPENTINE_*` or `TINE_*`
  variable (`export`, `NAME=value cmd`, `unset`, `env -u`, `os.environ[...]`)
  is a write to `env:NAME`.

### The oversight machinery is protected by default (0.85)

The kinds `monitor`, `oversight`, `policy`, `instrumentation`, `skill`,
`selector`, `reward`, `hook` and `proxy` join `grader`, `test`, `holdout`,
`sandbox` and `scorer`. Whatever the list says, `tine integrity check` adds
these surfaces (a list surface with the same name keeps its own globs):

| Surface | Kind | Globs |
|---|---|---|
| `oversight-policy` | `oversight` | `.tine/oversight.toml`, `.tine/oversight.sig.json` |
| `monitor-config` | `monitor` | `.tine/monitor*.toml`, `.tine/monitor*.json`, `.tine/monitors/**`, `monitors/**` |
| `policy-files` | `policy` | `.tine/policy/**`, `.tine/policies/**`, `.tine/*policy*.toml`, `.tine/*policy*.json` |
| `agent-hooks` | `hook` | `.claude/settings.json`, `.claude/settings.local.json`, `.claude/hooks/**`, `.codex/hooks.json`, `.codex/config.toml`, `.gemini/settings.json`, `.cursor/hooks.json`, `.hermes/**` |
| `proxy-config` | `proxy` | `.mcp.json`, `.cursor/mcp.json`, `.tine/mcp-proxy*`, `.tine/proxy*` |
| `monitor-env` | `monitor` | `env:OPENTINE_*`, `env:TINE_*` |

A write or delete tool call on one is `fail:protected-surface-modified`, and the
run's scores are tainted as for a grader edit.

**Default pins.** `tine oversight sign-policy`, `tine mcp-proxy --monitor CONFIG`
and `tine hook install` record the sha256 of the file they signed, loaded or
wrote in `.tine/integrity/defaults.json` when it lies inside the repository
(a user-level hook file outside it is not pinned; the containment `limit-edit`
detector still sees edits to it). A pinned file whose bytes changed is a
`fail:` like any pin, even when no recorded tool call touched it. The file is a
control file, so a run that writes it trips the check. `tine integrity pin`
folds the default surfaces and their pins into `.tine/protected.toml`; after a
legitimate edit, re-run the command that pins the file (or `tine integrity pin`)
and re-sign the list with a policy-role key. Where both pin a path, the signed
list wins.

**Protected reads.** A read tool call on a `grader`, `scorer`, `test` or
`monitor` surface is `advisory:protected-read` (a holdout read stays
`advisory:holdout-read`). It is reported, never blocks by default, and blocks
under `--strict`.

### How much the detectors catch

Be honest about the two kinds. On a blind held-out set of reward hacks the
detectors had not been tuned on, the advisory detectors caught **2 of 13**
before tuning. The seeded red-team corpus scores higher because the
detectors were tuned against it; that is not evidence they generalize.
Advisories are heuristics that route a reviewer's attention. The guarantee is
the `fail:` facts -- digests, signatures and policy -- and the refusals they
drive.

`--record FILE` also runs the advisory reward-hack detectors
(docs/SELF-IMPROVING-LOOPS.md) over a run record and adds their findings with
surface `detector`. They are `advisory:` codes: reported, never blocking unless
`--strict` (D12), and never a reason to file a taint. Only `fail:` facts taint a
run, and `tine promote` refuses a tainted candidate with `promote.score-tainted`.

| Code | Kind | Meaning |
| --- | --- | --- |
| `fail:protected-surface-modified` | hash fact | a pinned file's sha256 is not its pin (or the file is gone), or a write or delete tool call targets a protected path |
| `fail:protected-list-unsigned` | signature/policy fact | the list is not pinned by a policy-role key (see above) |
| `fail:protected-list-missing` | policy fact | there is no `.tine/protected.toml` |
| `advisory:test-deleted` | heuristic | a delete tool call on a `test` surface |
| `advisory:holdout-read` | heuristic | a read tool call on a `holdout` surface |

By owner decision D12 only `fail:` findings block (exit 1, `ok: false`);
`advisory:` findings are reported and block only with `--strict`. `--json`
prints the published schema `tine-cli-integrity-1`.

These are `tine integrity` codes. `tine verify`, the pyz, object kinds, wire
formats and the frozen vectors are unchanged (owner decision E9 refused).

## Taint is a claim convention

With `--key`, a run that tripped a `fail:` is marked tainted by an existing
`attestation` on the run whose claim follows `opentine.integrity.taint`:

```json
{"convention": "opentine.integrity.taint", "run": "run:sha256:...",
 "codes": ["fail:protected-surface-modified"], "findings_sha256": "<hex>",
 "protected_sha256": "<hex>"}
```

It is filed as `.tine/integrity/taints/<run hex>.json`. Any taint whose
signature verifies and whose claim and target name the run counts: a taint
can only refuse, so a stray one fails closed. An unsigned or retargeted file
is ignored.

A file can be deleted, so (0.59) the same signed attestation is also stored
as an object and held: a `tine hold` row `{"oid": <attestation>, "target":
"integrity-taint:<run>"}`, the way 0.57 keeps loop stops. The hold keeps the
attestation from every delete and prune, `tine hold release` refuses it (a
taint is never released), and promote and lineage read held taints as well as
filed ones, so deleting or rewriting the file does not un-taint. An unreadable
holds file counts as a taint (`holds-unreadable`, fail closed). `--json`
names the held object as `taint.hold` (`null` when the run is not stored in
the repository, where only the file records it).

## Promotion and lineage

- `tine promote CANDIDATE --baseline LABEL ... --repo PATH` refuses with
  `promote.score-tainted` when the candidate run has a filed or held taint, or, when
  the repository has a protected list, when the candidate trips any `fail:`
  against it at promotion time (an unsigned list included). A tainted score
  never moves a label.
- `tine lineage check VARIANT` and `tine lineage why VARIANT` report
  `lineage.score-tainted` for each variant on the walked ancestry whose
  mutation run has a filed or held taint, and exit 1: a tainted score cannot justify
  a lineage step.

## Canaries and contamination (0.60)

A *canary* is a string planted in a holdout so that a later copy of it, or a
model that codes it too cheaply, is evidence that the holdout leaked.

### Registration

`tine dataset canary-add TEXT --entropy-bits N --key KEY [--holdout NAME]`
signs a registration: an existing `attestation` (no new object kind) on the
target `sha256:<sha256 of TEXT>` whose claim follows the convention
`opentine.integrity.canary`:

```json
{"convention": "opentine.integrity.canary", "canary": "TEXT",
 "canary_sha256": "HEX", "entropy_bits": 96, "holdout": "NAME or null"}
```

It is filed as `.tine/integrity/canaries/HEX.json`. A canary is one line of
8 to 4096 UTF-8 bytes. `entropy_bits` is the declared information content of
the string: the fewest bits a model that never saw it needs to code it (at
most 8 per byte). A string of 24 random hex digits carries 96 bits.

A registration *counts* only when its signature verifies and its signer holds
the `dataset` role, and not the `optimizer` role, in key roles pinned by an
owner-signed trust bundle (0.59). Others are listed with `counted: false`.
`tine integrity scan` still looks for them, because finding more never weakens
a check. `tine dataset canary-check` does not use them to judge, so an
optimizer cannot lower a declared entropy by filing its own copy.
`canary-list` and every `--json` output give the digest, never the text.

### `tine integrity scan`

The scan reads every object in the repository, loose or packed, and searches
it in one pass for every registered canary. A canary is looked for as its UTF-8
bytes and as its JSON-escaped spelling. An object reachable from a `prompts/`
ref is reported as `prompts`, one reachable from a `memory/` ref as `memory`,
and any other object as `runs`. `--file PATH` (repeatable) also searches an
exported pack or bundle as raw bytes, under the surface `packs`. A compressed
export is searched as stored. The command exits 1 when any canary is found.

Objects are content addressed, so the scan keeps a derived index,
`.tine/integrity/canary-index.sqlite`. Per object id, the index stores the
digest of the canary set the object was scanned under and the canaries it
held. The index can be rebuilt by deleting it. A scan reads only the objects
not yet scanned under the current set. `counts` reports `objects`, `read`,
`cached` and `matches`. After a first scan, scanning a repository that grew by
*k* objects reads *k* objects, however many it held before
(`tests/test_061_canary.py` checks this by count at two repository sizes).
Registering a new canary changes the set digest, so the next scan reads every
object once.

### `tine dataset canary-check LENGTHS.json`

A scoring run reports the code length that the model under test assigns each
canary (`-log2 P(canary)` summed over its tokens). Since 0.60 the file is a
signed attestation (no new object kind) whose claim follows the convention
`opentine.integrity.canary-lengths`, with `target_id` the scoring run id:

```json
{"convention": "opentine.integrity.canary-lengths", "run": "RUN", "model": "candidate-7",
 "lengths": [{"canary_sha256": "HEX", "code_millibits": 31500}]}
```

Lengths are integer millibits, rounded down (a signed claim holds no floats).
The signer must hold the `scorer` role, and not the `optimizer` role, in the
owner-pinned key roles; `--run RUN` also requires the claim to name that run.
An unsigned, unpinned or unbound file is refused with `canary.unsigned`, and a
registration file that matches none of its held copies with `canary.tampered`
(both exit nonzero). A counted canary that is coded
below `entropy_bits - margin_bits` (`--margin-bits`, default 0) is evidence
that the model saw the holdout. The command refuses it with
`dataset.canary-below-entropy`, sets `ok` false and exits 1. The following are
advisory (owner decision D12) and block only with `--strict`:

- `dataset.canary-unscored`: a counted canary that the run did not score.
- `dataset.canary-unregistered`: a scored digest that no registration names.
- `dataset.canary-not-counted`: a registration that does not count.

The test suite uses a deterministic integer stub model (order-4 byte contexts,
add-one smoothing, integer bit lengths). Primed on the canary, it codes the
canary below its declared entropy and is refused. Unprimed, it is not.

### `tine dataset contamination HOLDOUT.jsonl --against CORPUS.jsonl`

The command reports two kinds of leak and records the method in the result:

- **exact**: each item's text (`input`, then `expected`) as a `blob` object id
  (schema 1, UTF-8). A holdout item is reported when its id is in a corpus or
  stored in the `--repo` repository.
- **near-duplicate**: word 5-gram shingles (lower-cased `\w+` tokens), MinHash
  signatures (128 permutations) and banded LSH (32 bands of 4 rows) to find
  candidates. The command then computes the exact Jaccard of the two shingle
  sets and reports pairs at or above `--threshold` (default 0.8), with both
  the exact and the estimated value. The number of candidate comparisons
  depends on how many near matches exist, not on the size of the corpus.

- Chunked: an item split across several corpus items, each under the
  threshold alone, is reported under `chunked` when the share of its shingles
  found in the union of corpus shingles (its `coverage`) is at or above the
  threshold.

- Embedding (0.74, opt-in with `--embedding-threshold T`): each item's text is
  embedded with the transcript backend (`transcript-hash/1`, or a local model
  named by `--embedding-backend MODULE:ATTR` whose weights digest is recorded)
  and items whose nearest corpus items have cosine similarity at or above `T`
  are reported under `embedding.near`, with the backend digest and threshold.
  This catches rewordings that keep the vocabulary but break 5-gram overlap.
  Items already reported as exact, near or chunked are not repeated. See
  docs/TRANSCRIPTS.md.

The command exits 1 on any leak.

### Mutations and what a writer can still do

Both the scan and the shingles fold text first (`opentine._canary_norm`):
Unicode NFKC, case folding, a fixed table of Cyrillic and Greek lookalike
letters, and dropping format characters such as zero-width spaces; the scan
also drops all whitespace and decodes JSON `\uXXXX` escapes. A canary written
in upper case, with extra or inserted spaces, a zero-width character or
lookalike letters is still found (`tests/test_061_canary_review.py`).
`canary-check` refuses a lengths file that scores none of the counted canaries
(`dataset.canary-none-scored`), and `--margin-bits` must leave every judged
canary a positive floor.

Since 0.60 each registration is also held (`tine hold` target
`holdout-canary:HEX`, never released), and readers take the union of the file
and its held copies: deleting a registration does not stop it counting, and
overwriting one is refused as `canary.tampered`. The held copies are skipped
by `integrity scan` (a registration holds its canary by design).

These checks are evidence, not a seal. Out of scope for 0.60: a canary split
across two objects (each object is scanned on its own); real paraphrases
(5-gram containment and MinHash see near copies only, until embeddings in
0.74); compressed packs passed as raw files (`--file` searches stored bytes);
and the full Unicode confusables table. A writer can also edit the derived
scan index so objects look already scanned (delete
`.tine/integrity/canary-index.sqlite` to rescan everything).

## Python and TypeScript

The pure check is `opentine._integrity.check`; the TS port is
`checkProtected` in `ts/verifier/src/protected.ts`. Both answer the shared
fixture `tests/data/integrity_check.json` (a parsed list, per-case
observations, expected `[code, path]` pairs), which is outside the frozen
vector family. `tests/test_060_integrity.py` regenerates the fixture from
`tests/integrity_helpers.py` and checks the Python answers;
`ts/verifier/test/protected.test.ts` checks the TS answers.

## Not yet

- Canaries (0.60): sealed holdout items (TINEAES), `tine dataset unseal`
  access records, exposure budgets and holdout rotation are separate plan
  items. The scan reads repository objects and raw files, so it does not
  inflate compressed exports. Embedding near-duplicates are opt-in
  (`--embedding-threshold`, 0.74) and see shared vocabulary, not meaning, unless
  a pinned local model is given. No TypeScript reader reads canary records
  yet.
- The remaining advisory heuristics of the plan (skip insertion,
  special-casing, visible/holdout gap, judge vs ground truth, fabricated tool
  evidence) and the seeded red-team corpus with its benign baseline.
- Taint propagation into curated datasets.
- Roles are only as safe as the owner pin: a loop that can write the
  operator's user config (`$XDG_CONFIG_HOME/opentine/`) or environment can
  pin its own owner key. Keep the owner key and that config out of the loop's
  reach.
- A taint on a run not stored in the repository is only a file (an
  attestation names a stored object), and deleting it un-taints that run.
- Observation of edits made outside captured tool calls is limited to the
  pinned digests on disk at check time.
