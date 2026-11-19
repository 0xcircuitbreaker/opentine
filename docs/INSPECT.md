# Inspect and METR interop

OpenTine reads and writes [Inspect AI](https://inspect.aisi.org.uk/) evaluation
logs and reads METR task-standard task families. Both directions are pure
file parsing: `inspect_ai` is not a dependency, and nothing is downloaded or
executed. Imports map into existing object kinds (runs, annotations, eval
verdicts); no object kind and no `tine verify` code is added.

## Importing an Inspect log

```
tine import inspect logs/2026-11-01_gsm8k.eval --repo . --key eval.key --evals evals/gsm8k
```

(`tine inspect import` is the same command.) Both log formats are read:

- `.json`: one `EvalLog` object (`version`, `status`, `eval`, `results`, `samples`);
- `.eval`: a zip holding `header.json` (or, from older writers,
  `_journal/start.json`) and one `samples/<id>_epoch_<n>.json` per sample. A zip with a member name twice, or any NaN, Infinity, overflowing float or integer past the digit limit, is refused. On export an id that is not a plain name (`..`, separators, other characters) or that collides with another id once printed (`1` and `"1"`) gets a digest member name `samples/sample-<sha256>_epoch_<n>.json`; the id itself is read from the member contents. Verdict item names that would collide likewise get a digest name, and scorers whose folder names collide are refused.

| Inspect | OpenTine |
| --- | --- |
| each sample (id, epoch) | one run on `heads/inspect/<task>-<eval>/s<index>` |
| sample messages | the run's steps, in order (the Inspect message is kept whole in `inputs.message` for user, system and tool turns and in `outputs.message` for assistant turns) |
| `eval.sandbox` | the run's first step: a `policy` step with `inputs["inspect.sandbox"]` set to the config as written (step evidence of the environment) |
| sample id, epoch, target, scores, output, metadata; eval header and results | the run annotation's `inspect` value (schema `opentine-inspect-sample-1`) |
| each scorer's scores (with `--key`) | one signed eval folder per scorer in `--evals DIR` (`eval.json` + `verdicts.jsonl` of `tine-eval-verdict/1`) |

The sample id keeps its JSON type: `1` and `"1"` are different samples, as
they are in Inspect. A second import of the same eval (same ref prefix) is
refused and writes nothing.

### Scores to eval verdicts

A score value maps into 0..1: Inspect's `C`, `I`, `P`, `N` to 1, 0, 0.5, 0; a
boolean to 1 or 0; a number already in 0..1 to itself. A value with no such
reading (a dict, a list, a number outside 0..1, other text) gets no verdict and
is listed under `skipped`; the raw value is kept in the annotation, so it is
neither lost nor guessed. The verdict's `scorer` is `inspect-<name>`, its item
is the sample id (`<id>@<epoch>` past epoch 1), `--threshold` (default 1) is
the pass mark, and `created_at` is the log's `eval.created` unless
`--created-at` is given. `tine eval verify evals/gsm8k/match` checks the
folder offline; an edited score fails with `eval-verdict.bad-signature`.

### Judge provenance from the log

When a scorer is model-graded and the log records its grader, the verdicts pin
that judge. The importer reads `results.scores[].params` for the scorer
(`model`, `template`, `instructions`) and, when `params.model` is not set,
`eval.model_roles.grader` (its `model` and the finite numbers in its `config`).
It builds an `opentine.judge-provenance/1` document (see docs/AUDIT_GAMES.md):
the prompt digest is over `template`, or over the recorded params when the log
has no template; the rubric digest is over `instructions`. Its `jp1+sha256:`
pin is the signed `scorer_version` of every verdict in that folder, and the
document is written beside them as `judge.json`. `tine eval verify` then fails
with `eval.summary-mismatch` when `judge.json` is edited or deleted. A scorer
whose log names no grader model keeps `scorer_version` `inspect:<name>` and gets
no `judge.json`; nothing is inferred. The `--json` row for each scorer reports
its `scorer_version`. Underscores in scorer names become `-` in the verdict's
`scorer` id (`model_graded_qa` signs as `inspect-model-graded-qa`).

## Exporting back to Inspect

```
tine export inspect --repo . --format eval --output gsm8k.eval
```

Every run under one import's ref prefix becomes one sample, in import order.
Sample ids, epochs, targets, scores and results come back exactly from the
annotation; messages are rebuilt from the steps. `--format json` (the default)
writes an `EvalLog` object, `--format eval` a zip with fixed member
timestamps, so the same runs always give the same bytes. With more than one
imported eval, name one with `--prefix` (the `ref_prefix` that
`tine import inspect --json` printed). Without `--output` the log goes to
stdout as raw bytes.

The acceptance test imports and exports five fixtures shaped like Inspect logs
for five pinned inspect_evals tasks and checks that sample ids and scores
round-trip exactly (`tests/test_065_inspect_roundtrip.py`). The fixtures are
small and synthetic; `tests/fixtures/inspect/MANIFEST.json` pins the task
names and the inspect_evals commit, and `scripts/gen_inspect_fixtures.py`
regenerates them.

## Signing logs as Inspect writes them

`opentine._inspect_hook` signs a log with a detached record beside it,
`<log>.tine-sig.json` (`opentine-inspect-log-sig/1`, schema
`opentine-inspect-log-sig-1`): the log's file name, byte length and SHA-256
under a `tine-sig/3` Ed25519 block over the domain
`opentine.inspect-log-sig.v1:`.

From an Inspect hooks module (with `inspect_ai` installed):

```python
from opentine._inspect_hook import register

register("/path/to/inspect.key")  # or set OPENTINE_INSPECT_KEY
```

`register` defines a `Hooks` subclass whose `on_task_end` signs the finished
log. Without `inspect_ai` it raises `ImportError`; nothing else in OpenTine
imports it. From the command line, `tine inspect sign LOG --key KEY` writes
the same record and `tine inspect verify LOG` checks it (exit 4 when any byte
of the log changed or the record was edited).

## Who may sign Inspect scores

A self-improving loop holds its optimizer key, so both commands check the
signer against the key roles of the owner-pinned trust bundle
(`opentine._key_roles_pin`, docs/SELF-IMPROVING-LOOPS.md). An unsigned
`.tine/key-roles.toml` can only refuse; it never grants.

| signer | `import --key` | `verify` | `import --require-signed` |
|---|---|---|---|
| holds the `optimizer` role | refused (`inspect.key-separation`, exit 4) | `refused`, exit 4 | refused |
| pinned `scorer` or `eval` key | signs, `signer_status: pinned` | `ok: signature valid, signer ... pinned` | imports |
| any other key, or roles unpinned | signs, `signer_status: unpinned` | `signature valid, signer unpinned`, exit 0 (exit 4 with `--strict`) | refused |

`verify` takes `--repo PATH` (default `.`) to find the roles and never prints
a bare `ok`. Unpinned is advisory by default (D12). `--require-signed` refuses
a log unless its detached signature verifies and its signer is a pinned
scorer key. No object kind and no `tine verify` code is added.

## METR task-standard families

```
tine import metr path/to/count_odds --out count_odds.jsonl
```

A family directory holds `<family>.py` with `class TaskFamily`. The file is
parsed with Python's `ast` module and never imported: `standard_version`,
`required_environment_variables`, and literal return values of `get_tasks`
and `get_permissions` are read. Each task becomes one dataset item
(`id` = `<family>/<task>`, `input` = `{family, task, data}`, metadata with the
standard version, environment variable names, permissions and the SHA-256 of
the family file and `manifest.yaml`). A `get_tasks` that builds its dict at
run time yields no items, and the output says `dynamic: true`.

## Bounds on hostile input

The log reader (`opentine._inspect_log`) refuses with `InspectLogError` (a
`ValueError`) before doing unbounded work:

| Limit | Value |
| --- | --- |
| log size | 256 MiB |
| one zip member, uncompressed | 64 MiB |
| whole zip, uncompressed | 512 MiB |
| zip members | 100 000 |
| compression ratio per member | 200 |
| JSON nesting depth | 64 |
| samples | 100 000 |
| messages per sample | 10 000 |

Encrypted members, unsupported zip versions and corrupt deflate streams are
refusals. The reader is the `inspect` target of `scripts/fuzz.py`, seeded from
the committed fixtures; triaged inputs live in `tests/fuzz_regressions/inspect/`.
The METR reader caps the family file at 4 MiB and task data nesting at 64.
