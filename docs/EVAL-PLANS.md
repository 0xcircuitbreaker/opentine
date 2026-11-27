# Eval plans and selection-adjusted promotion

From 0.86, a promotion can rest on an analysis that was fixed before the
candidate's outputs existed. `tine eval plan` signs the plan,
`tine eval run --plan` binds the scoring run to it, `tine eval reveal` opens
the committed seed after the runs, and `tine promote --plan --reveal` checks
that the run matched the plan and runs the planned test at an alpha corrected
for every candidate tried against the same baseline.

A loop that tests many variants and promotes the best one will promote noise
at any fixed alpha. A loop that chooses its analysis seed, its test or its
item set after seeing scores can do the same. The plan closes those three
doors: the candidate count, the test and the seed are committed first.

## Flow

```text
tine eval plan DATASET.jsonl --key SCORER_KEY --out plan.json --secret-out plan.secret \
    --max-candidates 20 [--metric pass_rate] [--reducer mean|pass@k|pass^k] [--epochs N] \
    [--test paired-bootstrap|permutation] [--alpha 0.05] [--resamples 2000] \
    [--correction holm|bonferroni] [--cluster-key FIELD] [--mde 0.05] [--min-coverage 1]
tine eval run DATASET.jsonl --scorer SPEC --key SCORER_KEY --out cand --outputs out.jsonl \
    --plan plan.json [--continue-on-error]
tine eval reveal plan.json --secret plan.secret --key SCORER_KEY --out reveal.json
tine promote RUN --baseline LABEL ... --plan plan.json --reveal reveal.json [--lineage DIR]
```

Keep `plan.secret` away from the optimizer: whoever holds it can compute the
analysis seed. Under the `rsi` profile the plan signer must be a pinned
`scorer` key, which is never an optimizer key.

## The plan (`opentine.eval-plan/1`)

The plan is an existing `attestation` whose `target_id` is the dataset
digest and whose claim follows `opentine.eval-plan/1`
(schema `opentine-eval-plan-1`):

| Field | Meaning |
|-------|---------|
| `dataset` | the dataset digest every planned run scores |
| `metric` | `score` (mean score) or `pass_rate` |
| `reducer` | how an item's epochs become one value: `mean`; `pass@k` (any epoch passes, best score); `pass^k` (every epoch passes, worst score) |
| `epochs` | runs per item (`pass@k` and `pass^k` need at least 2) |
| `test`, `resamples` | the paired test and its resample count |
| `alpha`, `correction` | the familywise alpha and `holm` (default) or `bonferroni` |
| `max_candidates` | how many candidates may be tested against one baseline under this plan |
| `cluster_key` | an item `metadata` field; items sharing a value are one unit of analysis |
| `mde` | the minimum detectable effect the power is reported at |
| `min_coverage` | the floor on scored / planned items |
| `seed_commitment` | `sha256:` over the 32-byte secret |

The reveal (`opentine.eval-plan-reveal/1`) names the plan's digest and the
secret. The analysis seed is the first 53 bits of SHA-256 over
`opentine.eval-plan-seed/1:<secret hex>:<plan sha256>`, so the seed is fixed
by the plan alone: re-running the analysis, re-running an eval or choosing a
policy seed cannot change it.

## Epochs, reducers and coverage

`eval run --epochs N` scores each item N times. Each `--outputs` line names its
`epoch` (0..N-1) and the verdict's `item` is `ID@eK`. `--continue-on-error`
records an item with no output as *skipped* and an item whose scorer raised
(including inside the isolated child) as *errored*, instead of aborting.

Every eval folder now holds `coverage.json`: an `attestation` signed by the
eval key, targeting the eval id, with the claim `opentine.eval-coverage/1`
(`planned`, `scored`, `skipped` and `errored` ids, `epochs`, the cluster of
every item, and the `plan_sha256` the run was bound to). `eval.json` repeats
the counts under `coverage`.

## What `promote --plan` checks

| Code | Refused when |
|------|--------------|
| `promote.plan-missing` | the policy sets `require_plan` (on under `profile = "rsi"`) and no `--plan` was given |
| `promote.plan-invalid` | the plan or reveal does not verify or is malformed |
| `promote.plan-signer` | the plan is not signed by a key in `eval_signers` (under `rsi`: a pinned `scorer` key that is not an optimizer key) |
| `promote.plan-mismatch` | the candidate scored another dataset, the candidate's `coverage.json` names another plan digest (a plan written or edited after the run), or either side's epochs or the candidate's cluster key differ from the plan |
| `promote.plan-after-outputs` | the plan's signing time is after the earliest candidate verdict |
| `promote.seed-not-committed` | no `--reveal`, or a reveal that names another plan, another signer, or a secret that does not open the commitment |
| `promote.coverage` | the candidate eval has no signed coverage, or scored / planned is below `min_coverage` |
| `promote.candidates-over-plan` | the lineage records more variants sharing the candidate's parents than `max_candidates` |
| `promote.uncorrected` | the planned test fails at the corrected alpha |
| `promote.eval-signer-role` | under `rsi`, a verdict signer on any side holds no pinned `scorer` role in the owner trust bundle, or is an optimizer key |

Without `--plan` and without `require_plan`, the promotion reports
`advisory:promote.no-plan` and does not block (owner decision D12). These are
command-level codes; `tine verify` does not judge plans.

### Correction

The candidate count is m = max(`max_candidates`, the lineage count), where
the lineage count is the number of recorded variants (`tine lineage record`)
whose parent set equals the candidate's. A loop that records more siblings
than it planned is refused; one that hides siblings cannot go below the
committed count. Bonferroni tests at alpha / m. Holm tests the k-th promotion
under the same plan (counted from the label history) at alpha / (m - k + 1).

A bootstrap interval at alpha needs at least 2 / alpha resamples to resolve
its bounds; with fewer, the analysis is `resolved: false` and the test fails.
Raise `resamples` (up to 100000) when m is large.

### Clusters, effective n and power

With a cluster key, each cluster contributes its mean paired difference, so
the effective n is the number of clusters. The analysis signed into the
decision (`plan.analysis`) reports `items`, `effective_n`, `delta`, the
interval or p-value, `se`, `mde_80` (the effect detectable at 80% power) and
`power_at_mde` (normal approximation). Power is reported, never a gate.

### What the decision records

`decision.json` carries `plan`: the plan digest and signer, the seed, m, the
lineage count, the Holm step, the correction, the alpha and corrected alpha,
the coverage counts and the analysis. The label history records the plan
digest of each promotion.

## The rsi profile

`profile = "rsi"` in the `[promote]` policy turns on `require_plan` (setting it
to `false` there is refused) and requires every verdict signer and the plan
signer to hold a pinned `scorer` role from the owner-signed trust bundle
(docs/EVALS-PROMOTION.md, "Pinning the key roles"), never an `optimizer` key.

## Limits

- Ordering uses signing times. The plan binding in `coverage.json` is signed
  by the scorer key, so under the `rsi` profile an optimizer cannot rebind a
  run to a plan written later; outside it, the eval signer is trusted not to.
  Outputs that were produced and discarded before the plan existed are not
  seen.
- The lineage count only sees recorded variants; `max_candidates` is the
  committed floor.
- Holm across promotions is applied in promotion order, not by sorting every
  candidate's p-value, so it is conservative only when the strongest
  candidate is promoted first.
- Power uses a normal approximation and is advisory.
