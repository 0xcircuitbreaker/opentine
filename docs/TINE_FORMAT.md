# OpenTine format policy

There are two distinct current formats:

- Portable `*.tine` compatibility files use `format_version == 2`; supported
  for reading: `{1, 2}`.
- A `.tine/` repository uses the verified v3 object model described below.

The v3 repository does not change the bytes or identity rules of existing v2
files. `Run.save(path.tine)` remains v2; `Run.save(directory)` is a compatibility
wrapper that writes v3 repository objects, but only when the directory is an
**initialized repository** — one holding `config.json` or `.tine/config.json`.
Against any other directory the call falls through to the v2 file writer and
fails with a bare `IsADirectoryError`. The repository path also refuses
`sign_key` and `draft`: a repository target is attested, not signed as an
artifact, which matters for the signing section below.

`Run.load()` reads v1 and v2 artifacts. A v1 file is **migrated to v2 in memory**
on load (the file on disk is never rewritten); re-saving it upgrades it to v2. An
older-unsupported or future `format_version` is rejected with an explicit error.
A file with **no** `format_version` is also rejected, unless it matches the
legacy 0.1.0 "linear" shape, which is best-effort imported instead (see
Compatibility). `tine migrate` upgrades a file in place or to a new path.

## Text validity (both formats)

Every string in either format is UTF-8 JSON text: a sequence of Unicode **scalar
values**. An unpaired UTF-16 surrogate — what `JSON.stringify` emits for a string
sliced mid-emoji, e.g. `"done \ud83d"` — is not one, and `json.loads` accepting
the escape does not make it representable. Such a string has no UTF-8 spelling,
so the v3 canonical form cannot encode it and other languages' readers disagree
about it (Go substitutes U+FFFD, changing every digest computed over the value;
serde refuses). Both the `.tine` writer and the `.tine` reader therefore refuse
it, naming the offending field path, so the two formats accept exactly the same
runs and `tine migrate-v3` never rejects an artifact this build wrote. A properly
paired escape is a normal scalar value and is unaffected — emoji are valid.

The same rule covers the byte spelling: raw CESU-8/WTF-8 surrogate bytes
(`ED A0 80`–`ED BF BF`, what a Java or `utf8mb3` producer emits) decode to the
same code unit without ever appearing as an escape, and are refused identically.
`ED 80 80`–`ED 9F BF` is ordinary U+D000–U+D7FF text and is unaffected.

opentine never substitutes a replacement character or drops the code unit: that
would rewrite recorded model output under a digest that claims fidelity. Repair
the offending string at its source. An archive an older build already wrote with
one is refused on read with that field path — the bytes stay on disk, untouched
and repairable — and the run index marks only that file unreadable, so `tine ls`
and `tine search` keep working for every other run in the directory.

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
| `graph.steps.<id>.billing` | explicit complete/partial/unknown/unmetered result and calculation provenance | absent |
| `metadata.tags` | normalized `list[str]`; emitted only when non-empty | absent |
| `metadata.budget_state` | derived breach record (never authoritative) | absent |
| `metadata.autosave` | autosave breadcrumb (stripped on final save) | absent |
| `metadata.migration` | append-only migration chain | recorded on migration |
| `metadata.integrity.signature` | `tine-sig/1` signature block | absent |
| `metadata.fork` | fork-act identity basis, recorded since 0.4.0 (see below) | absent |
| `metadata.fork_reason` | an MCP fork's stated reason, when given | absent |

The unpublished 0.2.1 development line (folded into 0.3.0) extends v2 without
changing `format_version`: normalized usage
may include input, output, cache-read, 5-minute/1-hour cache-write, reasoning,
provider total, and typed extra dimensions. `manifest.pricing` pins catalog
ID/hash/signature provenance, rate-card IDs, effective dates, and calculation
inputs. The numeric `cost` field remains the known subtotal.

`.tine_runs/index.json` is a **rebuildable sidecar** for `tine search` / `tine ls`
filters. It is a cache, never part of an artifact, and never authoritative.

## Integrity and the signed-payload boundary

`Run.save()` writes a SHA-256 digest to `metadata.integrity`. The digest covers
the canonical artifact body — **every top-level key except `metadata`**. It is a
checksum: it detects accidental corruption and many edits, but anyone who can
edit the file can recompute it.

`tine sign` adds a real signature at `metadata.integrity.signature`, at scheme
`tine-sig/2` since 0.7.1 (`tine-sig/1` blocks written by 0.3.0–0.7.0 are still
verified, under their own narrower view). It commits to a single canonical
*signed view* recomputed from content — never to the stored digest — so a body
edit plus a digest rewrite still fails verification.

| Field group | in digest | in `tine-sig/2` | in `tine-sig/1` |
|---|---|---|---|
| body: `format_version`, `run_id`, `created_at`, `status`, `graph` (+`usage`), `refs`, `transcript`, `manifest` (+`budget`), `policies`, `cache`, `draft` | yes | yes | yes |
| `metadata.{model_info, system_prompt, user_prompt, forked_from, fork_point, warnings, replay, context, next_harness, migration, fork}` | no | yes | yes (allowlist) |
| `metadata.tags` | no | yes | **no** (re-tagging never broke a v1 signature) |
| `metadata.{fork_reason, budget_state, autosave}`, any app-set key | no | yes | **no** |
| `metadata.integrity.*` | no | no (holds the signature itself) | no |
| signature header `scheme/alg/key_id/signer/signed_at` | no | yes | yes |
| signature `value`/`public_key` | no | no | no |

The digest's `metadata` exclusion is a deliberate boundary, not an oversight:
the digest is unkeyed, so it means "consistent", not "genuine". Metadata
authenticity comes from a `tine-sig/2` signature.

Use `Run.verify_integrity(...)` / `tine verify` before trusting an artifact, and
`Run.verify_signature(...)` / `tine verify --key-*` / `--pubkey` for authenticity.
See [SECURITY_MODEL.md](SECURITY_MODEL.md) for what a signature does and does
not prove.

## Compatibility

A 0.3.x reader loads and migrates v1, and also **best-effort imports the legacy
0.1.0 "linear" format** (no `format_version`, flat `steps`, short ids) on load —
recomputing full content-addressed step ids (so they change). A 0.1.x reader
**cannot** read v2, and once a v1 file is re-saved it becomes v2 (one-way).
`verify_integrity` checks an artifact under its own on-disk version and refuses a
newer (e.g. v3) file; the legacy 0.1.0 format has no digest verifiable under
current rules, so import it with `Run.load` / `tine migrate` rather than `verify`.

### Known v2 identity limitations

V2 keeps its released step-identity semantics for compatibility. One historical
fork-identity limitation was resolved in 0.4.0 (below); the step-ID one remains.

**Step IDs and redaction.** A step ID can be formed from in-memory fields before
save-time redaction, then the serialized step contains the redacted value. The
artifact-level digest still verifies, but that individual step ID may not
identify the exact serialized step bytes. V3 corrects this by redacting before
canonicalization and object hashing. The v2→v3 migrator always recomputes IDs
and never carries this identity claim forward.

**Fork run IDs (fixed in 0.4.0).** Through 0.3.0, `Run.fork` derived the new run
ID from the source run ID and the resolved fork point alone, so forking the same
run at the same step twice produced the **same** run ID: the `branch` argument
did not enter the ID, and neither did the MCP fork tool's `reason`, which was
recorded after the ID was formed. Two forks that diverged afterwards then carried
one ID; `tine fork` and MCP named the output file after that ID and refused the
second fork, while `Run.save` performed no such check, so a library caller that
saved both forks to that path silently kept only the last one.

Since 0.4.0 the run ID names the fork *act*, and `Run.fork` records its basis in
`metadata.fork`:

| `metadata.fork` field | meaning |
|---|---|
| `version` | derivation version (currently `1`) |
| `source` | the source run ID |
| `source_digest` | the 64-hex integrity digest the source *claims*, or `""` |
| `point` | the resolved fork point |
| `slice` | SHA-256 over the sorted retained step IDs |
| `slice_size` | number of retained steps |
| `branch` | the `branch` argument |
| `intent` | SHA-256 over the caller's declared intent (harness/prompt, replay/resume mode, or MCP reason) |
| `nonce` | a recorded 128-bit random value, or `""` for a deliberately reproducible fork |

The run ID is SHA-256 over that record, so it is always a 64-hex digest and two
fork acts of one point differ by their nonce. `metadata` is **outside** the
integrity digest — which covers the top-level `run_id` — so the ID itself, not
the stored record, is the commitment: editing `metadata.fork` cannot forge a
matching ID. `verify_fork_id(run)` re-derives the ID from the record and returns
`True` (the ID matches), `False` (the record was edited), or `None` (no verdict:
a pre-0.4.0 fork with no record, an explicit `new_run_id`, or a fork created in
a v3 repository, whose run object carries no record). It returns `None` — never
`False` — for any pre-0.4.0 fork, so it never accuses old provenance of
tampering, and it does not replace `verify_integrity`. An explicit `new_run_id`
still reproduces a chosen or legacy ID exactly, and `nonce=""` makes the derived
ID reproducible instead of unique. V3 run IDs
are content hashes over the stored object: two forks that differ in any recorded
content already differ in ID, and two that differ in nothing are the same object.

## V3 repository objects

The allowed types are `blob`, `event`, `run`, `attestation`, and `annotation`.
Objects are immutable envelopes with a positive safe-integer schema version and
either raw blob bytes or canonical JSON bytes. The typed ID is:

```text
TYPE:sha256:SHA256(TYPE || NUL || DECIMAL_SCHEMA || NUL || STORED_BODY)
```

JSON bodies use RFC 8785/JCS canonical encoding, including UTF-16 property-name
ordering and ECMAScript-compatible number rendering. Envelope headers are also
canonical. Decoding rejects malformed/non-canonical bodies, encoding/type
mismatches, and ID mismatches.

Python integer inputs outside JSON's interoperable safe range
`[-(2**53)+1, 2**53-1]` are rejected rather than rounded; encode 64-bit IDs,
nanosecond timestamps, and arbitrary-precision amounts as strings. IEEE-754
float values remain valid even when their canonical spelling uses integer digits.

Typed links are validated:

- event `parent_ids` and `causal_ids` point to events;
- event input/output/artifact fields point to blobs;
- run events, roots, and tips point to events, with roots/tips included in the
  run's event set;
- run manifests and other `*_blob` fields point to blobs;
- annotation `previous_id` points to an annotation;
- every linked object exists locally or is recorded as an explicit shallow
  boundary.

Deep `fsck` verifies all loose/packed objects, refs, causal links, and event
cycles. Client-side typed/path-aware redaction runs before JCS encoding and
hashing; raw credential-shaped text blobs are scrubbed before their ID is
computed.

### V2 migration boundary

Migration is strict by default and rejects a source with a failing integrity
check; `strict=False` / `--allow-unverified` is the explicit recovery path. It
stores the original v2 bytes as an unmodified legacy blob and records the source
artifact's integrity/signature result. It then creates newly redacted and hashed
v3 content plus a deterministic old→new map. The run object
sets `signature_scope = "legacy_blob_only"`; a legacy signature is never an
attestation over the generated v3 objects.

## Golden Fixtures

`tests/fixtures/` holds `golden_v1.tine` (still verified under v1),
`golden_v2.tine` (native v2), and `golden_signed_v2.tine` (HMAC-signed with a
fixed test key). Fast tests load, verify, migrate, fork, diff, and verify the
signature of these to guard format behavior.
