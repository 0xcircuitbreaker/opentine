# Changelog

## Unreleased — Security and integrity audit

- `tine promote --canary` now applies the gate's checks to the canary pair:
  the same item set (`promote.item-mismatch`), the same dataset
  (`promote.dataset-mismatch`) and at least `min_n` paired items
  (`promote.n-below-minimum`). An empty, tiny or cherry-picked canary used to
  pass silently, and a single bad item could revert an honest promotion.
- The promotion gate (main, holdout and canary pairs) refuses evals whose
  scorer, `scorer_version` or `threshold` differ between the sides, or vary
  within one side, with the new command-level refusal `promote.scorer-mismatch`.
  A candidate scored under a lower threshold could raise `pass_rate` without
  improving.
