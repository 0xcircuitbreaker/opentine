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
  `protected-list` surface whether or not the list names them.

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

## Python and TypeScript

The pure check is `opentine._integrity.check`; the TS port is
`checkProtected` in `ts/verifier/src/protected.ts`. Both answer the shared
fixture `tests/data/integrity_check.json` (a parsed list, per-case
observations, expected `[code, path]` pairs), which is outside the frozen
vector family. `tests/test_060_integrity.py` regenerates the fixture from
`tests/integrity_helpers.py` and checks the Python answers;
`ts/verifier/test/protected.test.ts` checks the TS answers.

## Not yet

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
