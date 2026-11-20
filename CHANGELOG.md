# Changelog

## Unreleased — Security and integrity audit

- `tine merge-history apply` no longer copies label state files from
  `--theirs-state`. A loop could hand-write `.tine/promotion/<label>.json` in its
  own clone (no signed decision, no VSA) and a routine merge would land its
  candidate on the label without oversight, holdout, monitor or guards. A label
  that differs is now refused with `history-merge.label-gated`; labels move only
  by `tine promote`.
