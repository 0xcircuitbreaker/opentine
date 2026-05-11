# `.tine` Format Policy

Current format: `format_version == 1`.

Opentine currently promises compatibility for the active v1 format only. `Run.load()` rejects missing, old, or future `format_version` values with an explicit error. Migration tooling and long-term multi-version read support are future work.

## Top-Level Fields

`format_version`, `run_id`, `created_at`, `status`, `graph`, `refs`, `transcript`, `manifest`, `policies`, `cache`, `metadata`.

The `graph` field stores a content-addressed DAG:

- `graph.steps` maps full SHA-256 step IDs to step objects.
- `graph.order` stores stable traversal order for display and compatibility.
- `parent_ids` records graph ancestry.
- `refs` records named tips such as `main` and fork metadata.

Step IDs are SHA-256 hashes over a canonical immutable payload containing the step kind, parent links, inputs, outputs, model/tool metadata, and error payload. Timestamps, duration, and cost are recorded data, but they are not part of the step ID.

## Integrity Metadata

Saved artifacts include:

```json
{
  "metadata": {
    "integrity": {
      "algorithm": "sha256",
      "digest": "..."
    }
  }
}
```

Use `Run.verify_integrity(path_or_data)` or `tine verify <run.tine>` before trusting an artifact copied through email, chat, or artifact storage.

The digest is a checksum, not a signature. It currently covers the redacted artifact body outside `metadata`; metadata-only edits are outside the digest boundary.

## Golden Fixtures

The repository includes a static v1 golden fixture at `tests/fixtures/golden_v1.tine`. Fast tests load it, verify its digest, save it again, fork it, and diff it to guard the current format behavior.
