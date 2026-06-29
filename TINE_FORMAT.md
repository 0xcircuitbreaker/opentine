# `.tine` Format Policy

Current format: `format_version == 2`. Supported for reading: `{1, 2}`.

`Run.load()` reads v1 and v2 artifacts. A v1 file is **migrated to v2 in memory**
on load (the file on disk is never rewritten); re-saving it upgrades it to v2. A
missing, older-unsupported, or future `format_version` is rejected with an
explicit error. `tine migrate` upgrades a file in place or to a new path.

## Top-Level Fields

`format_version`, `run_id`, `created_at`, `status`, `graph`, `refs`, `transcript`,
`manifest`, `policies`, `cache`, `metadata`, and (only on autosave checkpoints)
`draft`.

The `graph` field stores a content-addressed DAG:

- `graph.steps` maps full SHA-256 step IDs to step objects.
- `graph.order` stores stable traversal order for display and compatibility.
- `parent_ids` records graph ancestry.
- `refs` records named tips such as `main` and fork metadata.

Step IDs are SHA-256 over a canonical immutable payload: step kind, parent links,
inputs, outputs, model/tool metadata, and error. **Timestamps, duration, cost,
and token `usage` are recorded data but are NOT part of the step ID** — so two
steps with identical content but different cost share an ID (and surface as a
`changed` pair in `diff`, never as add/delete).

## What's new in v2 (delta over v1)

| JSON path | meaning | default for a migrated v1 file |
|---|---|---|
| `format_version` | now `2` | set to 2 |
| `draft` (top-level bool) | autosave checkpoint marker; emitted only when `true` | absent |
| `manifest.budget` | `{max_cost, max_steps, max_duration, max_usage, on_breach}` | absent |
| `graph.steps.<id>.usage` | `{input, output}` token counts; emitted only when present | absent |
| `metadata.tags` | normalized `list[str]`; emitted only when non-empty | absent |
| `metadata.budget_state` | derived breach record (never authoritative) | absent |
| `metadata.autosave` | autosave breadcrumb (stripped on final save) | absent |
| `metadata.migration` | append-only migration chain | recorded on migration |
| `metadata.integrity.signature` | `tine-sig/1` signature block | absent |

`.tine_runs/index.json` is a **rebuildable sidecar** for `tine search` / `tine ls`
filters. It is a cache, never part of an artifact, and never authoritative.

## Integrity and the signed-payload boundary

`Run.save()` writes a SHA-256 digest to `metadata.integrity`. The digest covers
the canonical artifact body — **every top-level key except `metadata`**. It is a
checksum: it detects accidental corruption and many edits, but anyone who can
edit the file can recompute it.

`tine sign` adds a real signature at `metadata.integrity.signature` (scheme
`tine-sig/1`). It commits to a single canonical *signed view* recomputed from
content — never to the stored digest — so a body edit plus a digest rewrite
still fails verification.

| Field group | in digest | in signature |
|---|---|---|
| body: `format_version`, `run_id`, `created_at`, `status`, `graph` (+`usage`), `refs`, `transcript`, `manifest` (+`budget`), `policies`, `cache`, `draft` | yes | yes |
| `metadata.{model_info, system_prompt, user_prompt, forked_from, fork_point, warnings, replay, context, next_harness, migration}` | no | yes (allowlist) |
| `metadata.tags` | no | **no** (mutable labels — re-tagging never re-signs) |
| `metadata.{budget_state, autosave}` | no | no (derived/transient) |
| `metadata.integrity.*` | no | no (holds the signature itself) |
| signature header `scheme/alg/key_id/signer/signed_at` | no | yes |
| signature `value`/`public_key` | no | no |

Use `Run.verify_integrity(...)` / `tine verify` before trusting an artifact, and
`Run.verify_signature(...)` / `tine verify --key-*` / `--pubkey` for authenticity.
See `SECURITY_MODEL.md` for what a signature does and does not prove.

## Compatibility

A 0.2.x reader loads and migrates v1. A 0.1.x reader **cannot** read v2, and once
a v1 file is re-saved it becomes v2 (one-way). `verify_integrity` checks an
artifact under its own on-disk version and refuses a newer (e.g. v3) file.

## Golden Fixtures

`tests/fixtures/` holds `golden_v1.tine` (still verified under v1),
`golden_v2.tine` (native v2), and `golden_signed_v2.tine` (HMAC-signed with a
fixed test key). Fast tests load, verify, migrate, fork, diff, and verify the
signature of these to guard format behavior.
