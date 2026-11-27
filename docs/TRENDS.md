# Capability trends over lineage generations (0.72)

`tine trends` reports how the variants of a self-improving agent loop perform,
generation by generation, along the signed lineage graph that `tine lineage
record` builds (docs/LINEAGE.md). Every number comes from signed records, and
`--export` writes a file from which a browser recomputes the same numbers,
byte for byte.

```text
tine trends [--loop LOOP] [--alpha 0.05] [--seed 0] [--resamples 2000]
            [--task-lengths FILE] [--promotion-policy TOML]
            [--fail-on-regression] [--export FILE] [--json] --repo PATH
tine trends --sign-lengths LENGTHS.json --key KEY --dataset DIGEST [--suite NAME] [--at TIME]
```

## Inputs, and what counts

| Input | Counts when |
| --- | --- |
| Variant record (`opentine.lineage.variant`, 0.58) | It is well formed and Ed25519-signed by its `signer` (the `tine lineage check` record rules). Otherwise it is listed under `excluded` as `lineage.record-invalid`. |
| Its justifying eval verdicts (`tine-eval-verdict/1`) | Every verdict verifies, hashes to the record and, with signers pinned, is signed by a `scorer` key that is not an optimizer key. Otherwise the variant keeps its row with no items and the flag `lineage.evidence-missing` or `lineage.signer-untrusted`. |
| Cost | Signed `spend` entries of the 0.69 budget ledger whose `run` is the variant's mutation run (`total_cost`, in micro-USD). |
| Task lengths (`opentine.trends.task-lengths/1`) | Signed, `signer` is the key the signature rests on, and that key holds the `dataset` role in the owner-pinned trust bundle (0.59) and is not an `optimizer` key. Otherwise no variant gets a horizon and `lengths.status` says why: `missing`, `invalid`, `roles-unpinned` or `signer-untrusted`. |

A variant's **generation** is its depth in the parent graph: a root is 0, any
other variant one more than its deepest recorded parent. A parent with no
record does not count (the variant also gets `lineage.parent-missing`).
Variants on or behind a parent cycle are excluded as `lineage.cycle`.

## Flags

A variant's `flags` are lineage codes:

* `lineage.score-tainted`: its mutation run carries a signed 0.59 taint
  (`tine integrity check --key`);
* `lineage.memory-quarantined`: its mutation or eval runs were served a note
  quarantined under 0.61;
* `lineage.evidence-missing`, `lineage.signer-untrusted`: the metrics are
  withheld (no items);
* `lineage.decision-mismatch`: reported as found;
* `lineage.parent-missing`: a cited parent's record is absent, so no paired
  comparison against it runs; the variant is listed in `unchecked[]`.
* `holdout.query-over-budget` (0.86): an eval it cites has a held holdout
  query record that went over the holdout's query budget, or the holds cannot
  be read (docs/HOLDOUTS.md).

A flagged variant's numbers are still printed, but it is never a generation's
`best`.

## Numbers

Per variant (`variants[]`):

* `score` and `pass_rate`: the mean over eval items and a 0.57 paired-bootstrap
  interval (the `tine eval compare --ci` code, integer micro-units, positions
  `floor(alpha/2*R)` and `ceil((1-alpha/2)*R)-1`);
* `cost_per_success`: cost over passed items, or `null`;
* `horizon`: the task length (minutes) at which a logistic fit of success on
  `log2(minutes)` crosses 50%, with a studentized bootstrap interval: items are
  resampled with replacement, each resample's crossing is divided by its own
  delta-method standard error, and the interval is `x - t[high]*se, x -
  t[low]*se`. `reason` is `fewer-than-two-lengths` or `no-fit` (success does not
  fall with length) when there is none. A resample that does not fit counts
  as an infinite t on the side its pass rate points to; an infinite bound is
  `null`. `failed_resamples` counts them;
* `vs_parents`: per parent, a paired bootstrap of the per-item difference on
  the items both scored. A significant drop in `score` or `pass_rate` is a
  regression.

Per generation (`generations[]`): variant, flagged and regression counts, and
the best unflagged variant by mean score with its horizon. `regressions[]`
lists every variant/parent pair that regressed. `tine trends` exits 0 unless
`--fail-on-regression` is given and there is a regression or an `unchecked`
variant (below).

## What a loop cannot do to the report

The loop signs its own lineage records, so the report does not trust what the
records alone could fake:

* **Unpinned eval signers.** With no owner-pinned `scorer` role and no
  `--promotion-policy`, a verdict's signer is proven but not trusted, so every
  variant that cites evals gets `lineage.signer-untrusted` and its metrics are
  withheld.
* **Hiding a regression by dropping evidence.** `unchecked[]` lists each
  variant whose regression status cannot be established: excluded records,
  withheld metrics (`lineage.evidence-missing`, `lineage.signer-untrusted`),
  missing parent records (`lineage.parent-missing`: deleting a parent's record
  must not skip the comparison silently) and relabelled runs. `--fail-on-regression` exits 1 when it is not empty.
* **Re-rooting.** `tine lineage record` refuses to re-sign an existing variant
  with a different claim (new parents or evals): records are append-only. A
  mutation run recorded as more than one variant gets the command-level flag
  `trends.run-relabelled` on each.
* **Cherry-picking runs by citation order.** Items are keyed by
  `<dataset>:<item>`. An item scored by more than one cited eval keeps its
  worst verdict, whatever order the evals are cited in.
* **Swapping the task suite.** Task lengths name the eval `dataset` digest
  they were signed for (`--sign-lengths ... --dataset sha256:HEX`) and apply
  only to verdicts of that dataset.
* **Cost.** A spend entry counts only when its signer holds the pinned
  `runner` role and no `optimizer` role. A counted `total_cost` that is not a
  finite non-negative number makes that run's cost `null`.

The seed and resample count are the caller's choice and are recorded in the
export; anyone can rerun with other seeds (see "Not covered").

## The export and browser recomputation

`--export FILE` writes `opentine-trends/1`: the inputs above as canonical JSON
(RFC 8785) plus `reported`, the numbers printed. `opentine/data/trends/recompute.mjs`
is a standalone ES module (no dependencies) for a hosted trends page:

```js
import { check } from "./recompute.mjs";
const result = check(await (await fetch("trends.json")).json());
// result.ok: the browser's numbers equal the reported ones, byte for byte
```

and `node recompute.mjs FILE` prints the canonical JSON of the recomputed
numbers. Python's `opentine._trends.compute` is the same function.

Byte equality holds because no number depends on a platform library:

* resampling uses SplitMix64 seeded with FNV-1a 64 of
  `opentine.trends/1:<seed>:<variant>:<metric>` (`randrange(n)` rejects draws
  at or above the largest multiple of n), not Python's `random`;
* score, rate and cost arithmetic is in integers, rounded half-even to six
  places;
* the horizon fit uses only IEEE-754 double `+ - * /` and comparisons: `exp`,
  `log` and `sqrt` are computed by range reduction and a fixed number of series
  or Newton terms, and minutes print as `floor(v*1e6 + 0.5)` micro-units.

`--seed` is limited to 0..2^53-1 so a browser reads it exactly; `compute`
refuses an export with a larger seed.

## Acceptance: planted horizons

`tests/data/trends_horizon_synth.json` (written by `scripts/gen_trends_synth.py`)
holds 100 datasets, seeds 0..99, drawn from the known logistic
`p = 1/(1+exp(0.9*(log2 m - log2 30)))`: 12 task lengths from 1 to 1920
minutes, 16 tasks each, planted 50% horizon 30 minutes.
`tests/test_072_trends_horizon.py` fits each with 1000 resamples and requires
the planted horizon inside the 95% interval in at least 95 of the 100; it is
inside in 96.

Recorded measurements of the same method (not tests):

| Data | Resamples | Planted horizon inside the 95% interval |
| --- | --- | --- |
| committed seeds 0..99 | 200 | 95 / 100 |
| committed seeds 0..99 | 400 | 94 / 100 |
| committed seeds 0..99 | 1000 | 96 / 100 |
| further seeds 100..699 | 1000 | 566 / 600 (94.3%) |
| further seeds 100..699, Wald interval (no bootstrap) | - | 565 / 600 (94.2%) |

The coverage on the larger sample is about 94% (binomial standard error about
0.9 points), so 95-of-100 on any one set of 100 seeds is near the method's
nominal rate rather than a wide margin.

## In `tine query`

`tine query index --rebuild` writes one `trend_points` row per variant that
`tine trends` would report, trusted the same way (pinned `scorer` keys, no
optimizer): `generation`, `n`, mean `score`, `pass_rate`, `cost_per_success`,
`flags` and `withheld`. The row's `oid` is the variant's lineage record, so

```sql
SELECT t.generation, t.variant, t.score, l.signer
FROM trend_points t JOIN lineage_variants l USING (variant)
ORDER BY t.generation
```

lists the trend by lineage generation. Task lengths are not read there, so the
horizon, intervals and regressions stay in `tine trends`. The index is
non-authoritative; `--verify` re-derives each point from the lineage folder.

## Freeze

No object kinds and no `tine verify` codes. `opentine.trends/1` (the export)
and `opentine.trends.task-lengths/1` are file conventions with published
schemas (`opentine-trends-1`, `opentine-trends-task-lengths-1`); `tine trends
--json` prints `tine-cli-trends/1`. The command writes nothing to the
repository except, with `--sign-lengths`, the task-lengths file; deleting that
file only withholds the horizon (`missing`).

## Not covered

Versioned task suites, human baseline records, AI-assisted vs unassisted
paired runs and perceived vs measured speed are a separate command,
`tine uplift` (docs/UPLIFT.md), shipped in the same release; task lengths here
are only the per-item minutes the horizon needs.

A caller can rerun `tine trends` with many seeds and report the one it likes;
the seed is in the export, but nothing pins it. Lineage, eval and task-length
files are plain files: a loop with write access to the folder can still delete
a variant record outright (only re-signing through `tine lineage record` is
refused), and nothing holds them.
