# Scorer isolation and evaluator contracts (0.85)

A self-improving loop is judged by its scorer. If the candidate can reach the
scorer's process, its environment, its helper modules or its data files, it
can change the score without improving. These tools keep the scorer out of
the candidate's reach and make changes to it visible:

| Tool | What it does |
|------|--------------|
| `tine eval run --isolate` | runs a `python:` scorer in an isolated child process and pins its full import closure |
| `--expect-closure DIGEST` | refuses the eval when the closure differs from a pinned one |
| `--contract FILE` | enforces evaluator invariants (determinism, anchors, output shape) |
| `tine eval rescore DIR` | re-runs the recorded scorer under isolation and signs agree/disagree |
| `tine eval lint FILE...` | flags code that inspects its call stack, the garbage collector or the grader |
| `[promote] scorer_isolation` | reports or refuses in-process scorers at promotion |

None of these adds an object kind or a `tine verify` code. `scorer.json`,
contracts and rescore reports are claim and file conventions; their schemas
are `opentine-scorer-closure-1`, `opentine-scorer-contract-1` and
`opentine-rescore-report-1`.

## The isolated runner

`tine eval run DATASET --scorer python:FILE.py:FUNC --isolate --key KEY --out DIR`
starts `python -I -B` on `opentine/_scorer_child.py`. The child imports nothing
from opentine before the scorer, so it holds no signing key: it returns scores
and the files it loaded, and the parent hashes the files and signs. The child:

- starts with an **empty environment** (on Windows only `SYSTEMROOT`, which the
  interpreter needs) and in a **fresh empty working directory** that is
  deleted afterwards. `os.environ` is replaced by an empty mapping that
  records any read from non-stdlib code as a breach.
- lowers its **CPU, address-space, file-size (0) and open-file limits**, both
  soft and hard, on POSIX (`--cpu-seconds`, default 60; `--memory-mb`, default
  2048). The parent kills the child's whole process tree at `--timeout`
  (default 120 s) and bounds what it reads from the child (8 MiB).
- on **Linux** moves into a new user and network namespace, so no network
  interface is reachable (`network: namespace`). When the kernel refuses
  unprivileged namespaces, and on macOS and Windows, sockets are refused only by
  the audit hook (`network: audit`).
- installs an **audit hook** that refuses sockets, subprocesses, `os.system`,
  `exec`/`spawn`/`fork`, `ctypes`, signals, `gc` and trace hooks, every file
  write, and every file read or directory listing outside the interpreter's
  own library, the scorer's import paths and the `--scorer-input` files.
  Bytecode is read only from an empty prefix, so a planted `.pyc` never runs.
  Hard links, symbolic links, timestamps, ownership, extended attributes and
  SQLite databases count as writes. Modules that start processes, load native
  code, open other databases or start sub-interpreters without an audit event
  (`_posixsubprocess`, `subprocess`, `ctypes`, `_interpreters`, `_dbm`, the
  CPython test modules) are dropped from `sys.modules` and refused on import,
  and `os.mkfifo` and `os.mknod` are replaced by refusals.

Any breach, a blown limit or the timeout refuses the eval with
`scorer.isolation-breach`; no eval folder is written. A scorer that raises is a
plain error (exit 1).

`scorer.json` records `isolation.level`: `full` when the namespace and the
limits both took effect, `partial` otherwise. The level is recorded honestly
and never upgraded. Isolation is a best effort inside one interpreter, not a
sandbox: code that defeats the audit hook (a native extension, for example) is
outside it. For a hard boundary, run the whole eval inside a container or VM.

Paths: a `python:FILE.py:FUNC` scorer may import modules from its own
directory. A `python:MODULE:FUNC` scorer may import from the parent's
`sys.path`, so reads under those directories are allowed too; prefer the file
form. The child's working directory is empty, so a scorer opens its inputs by
absolute path.

## The closure pin

After the call, the child reports every non-stdlib module in `sys.modules`
and every other file it read; the parent hashes each one itself. That report
comes from the same interpreter as the scorer, so the parent does not rely on
it: it also lists and hashes every file under the scorer's own import
directories (not the standard library or site directories, and not
`__pycache__`) and records them under `data`. A helper hidden from the report
is still in the closure. More than 2000 files there refuses the eval with
`scorer.closure-too-large`: keep each scorer in a directory of its own.
Installed packages are covered only by `--lockfile`.
`scorer.json` sits beside the verdicts:

```json
{"convention": "opentine.scorer-closure/1",
 "target": "python:sc/good.py:score", "python": "3.12.3",
 "modules": [{"name": "good", "sha256": "..."}, {"name": "helper", "sha256": "..."}],
 "data": [], "inputs": [{"file": "answers.txt", "sha256": "..."}],
 "lockfile": "sha256:..." , "contract": null,
 "isolation": {"level": "full", "network": "namespace", "limits": true, "env": "empty"},
 "limits": {"cpu_seconds": 60, "memory_mb": 2048, "timeout_seconds": 120,
            "output_bytes": 8388608}}
```

`--lockfile FILE` adds the lockfile's digest. The **closure digest** (the
`closure` field of `eval run --json`) is `sha256:` over the code-bearing fields
only (`target`, `python`, `modules`, `data`, `inputs`, `lockfile`, `contract`), so
the same scorer on another machine has the same closure. The **pin**,
`sc1+sha256:` over the whole document, is every verdict's `scorer_version`, so the
closure is inside the signed verdict body. `tine eval verify` recomputes the
pin: an edited or missing `scorer.json` fails with `eval.summary-mismatch`, and
editing `scorer_version` to match breaks the verdict signature.

Pin the closure digest once, for example in CI configuration or next to
`protected.toml`, and pass it as `--expect-closure`: a helper module changed
after pinning refuses the eval with `scorer.closure-mismatch`.

A native extension is hashed as a file, but what it loads at run time is not
followed.

## Trusted re-scoring

`tine eval rescore DIR --dataset DATASET --key KEY [--outputs FILE]` verifies the
eval, reads `scorer.json`, re-runs the recorded target under isolation on the
given outputs (or the dataset's own `output` fields), and compares each item's
score with the signed verdict and the new closure with the recorded one. It
writes a signed `opentine.rescore-report/1` (domain
`opentine.rescore-report.v1:`, signer bound to the signing key) with
`verdict: agree` only when the closure is the same and every score is. It
exits 4 on disagreement. An eval with no `scorer.json` cannot be re-scored.

This catches results that were edited without touching any protected file: if
the reported verdicts were computed from a tampered cached output file, the
re-score of the real outputs disagrees, and the disagreement is signed.

## Evaluator contracts

`--contract FILE` names an `opentine.scorer-contract/1` JSON file:

```json
{"convention": "opentine.scorer-contract/1",
 "deterministic": true,
 "anchors": [{"item": {"id": "x", "expected": [1, 2]}, "output": [0, 2], "score": 0.5}],
 "output_schema": {"type": "array"},
 "output_length": {"min": 1, "max": 10000},
 "length_relation": {"field": "expected", "relation": "eq"}}
```

- `deterministic`: everything is scored twice and the scores must be equal.
- `anchors`: inputs with known scores; a scorer whose logic changed (for
  example, one that silently drops part of a list before comparing) scores
  them differently.
- `output_schema`, `output_length` and `length_relation` check each output
  before it is scored (`eq`, `le` or `ge` against `len(item[field])`).

A violation refuses the eval with `scorer.contract` instead of reporting a low
or inflated score. With `--isolate` the contract's digest is in `scorer.json`
and so inside the signed pin. A timing floor is not part of a contract, since
it would depend on the machine.

## The introspection lint

`tine eval lint FILE... [--grader PATH]...` parses each file and reports:

| Code | Flags |
|------|-------|
| `advisory:introspection.stack` | `sys._getframe`, `inspect` frame and stack calls, `traceback` stack walks, frame attributes (`f_back`, `f_locals`, ...), `sys.settrace` / `sys.setprofile` |
| `advisory:introspection.gc` | `gc.get_referrers`, `gc.get_objects`, `gc.get_referents` |
| `advisory:introspection.dynamic` | `eval`, `exec`, `compile`, `__import__`, `importlib.import_module`, `getattr` with a computed name |
| `advisory:introspection.grader-read` | a string naming a `--grader` file, a test file or a `tests/` directory |
| `advisory:introspection.unparsed` | a file that is not valid Python |

Names built at run time evade it, so its findings are advisory and the exit
status is 0 (owner decision D12). `--strict` exits 4 on any finding, for CI jobs
that choose to block. Run it over the files a candidate changed and over the
scorer itself.

## Promotion

`tine promote` checks the scorer of every eval it reads. A `python:` or
`plugin:` scorer without an `sc1+` closure pin ran in-process. By default the
output's `advisories` lists `advisory:scorer.in-process` and nothing is
blocked. The signed promotion policy can require isolation:

```toml
[promote]
scorer_isolation = "required"   # or profile = "rsi", which requires it
```

Then an in-process scorer refuses the promotion with
`promote.scorer-in-process`. `profile = "rsi"` cannot be combined with
`scorer_isolation = "advisory"`. Built-in scorers (`exact`, `regex:`,
`json-schema:`) and `llm-judge:` are not in-process code and are not flagged.

Since 0.86 `profile = "rsi"` also requires a pre-registered eval plan
(`promote.plan-missing`), a lineage record for the candidate
(`promote.lineage-missing`), eval and plan signers that hold a pinned `scorer`
role in the owner trust bundle and are not optimizer keys
(`promote.eval-signer-role`), and holdout query budgets as a refusal
(`promote.holdout-query-budget`). See docs/EVAL-PLANS.md and docs/HOLDOUTS.md.

## Not covered

- `tine eval ci` runs scorers in-process; it does not take `--isolate` yet.
- `plugin:` scorers are not isolated; they are flagged as in-process.
- The lint reads whole files, not diff hunks.
- `tine verify` does not judge closure pins offline; `tine eval verify` does.
