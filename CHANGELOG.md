# Changelog

## Unreleased — Security and integrity audit

- `tine merge-history` refuses a snapshot whose holds name anything but a
  run oid and a 1..1024 character target. Before, `apply` could write such a
  row into `.tine/holds`, after which every hold read failed (holds-merge-poison).

## 0.67.0 — Merging run histories (2026-11-20)
