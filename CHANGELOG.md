# Changelog

## 0.3.0 — 2026-07-15

Git-shaped repository foundation for agent runs. Portable `*.tine` files remain
v2; repository objects use the new verified v3 format.

### Added

- Dependency-free trusted semantic kernel (≤250 physical lines) with RFC 8785
  canonical JSON, raw blobs, typed SHA-256 IDs, immutable envelopes, typed
  parent/causal links, verification, and a minimal repository protocol.
- `.tine/` object storage, refs/reflogs, CAS ref updates, semantic log/diff,
  fork, causal context slices, deep `fsck`, deterministic packs, shallow
  boundaries, missing-object negotiation, fetch/push, and clone.
- `blob`, `event`, `run`, `attestation`, and separately versioned `annotation`
  objects. Redaction occurs before canonicalization and hashing.
- V2 migration that retains the exact legacy bytes and original verification
  result, recomputes v3 identities, stores a deterministic ID map, and scopes
  the legacy signature to the legacy blob only.
- Normalized native/JSONL/OpenTelemetry/framework trace importers and a live
  `Recorder` workflow for record, resume, fork, evaluate, approve, and promote.
- Python and MCP search, inspect, minimal context, semantic diff, fork/resume,
  evaluation, attestation, and promotion operations.
- Minimal self-hosted HTTP remote with discovery, filtered/shallow fetch,
  resumable pack transfer, tenant-scoped RBAC, static-token/OIDC seams,
  encrypted filesystem objects, SQLite metadata, hash-chained audit records, and
  pluggable storage/index/identity/authz/key/audit/retention/admission policies.
- CLI commands: `init`, `fsck`, `repo-log`, `object`, `pack`, `migrate-v3`,
  `fetch`, `push`, `clone`, and `serve`.

### Fixed (post-audit hardening)

- Canonical JSON now rejects integers beyond the exactly representable range
  (±(2**53−1)) instead of silently coercing them to a float, which could collide
  two distinct values onto one object id and corrupt stored values.
- Pack transfer and decompression are bounded (maximum 256 MiB), reject trailing
  compressed data, and stream client downloads under the same cap, so a zlib bomb
  from an untrusted remote or authenticated writer cannot grow memory without
  bound. The reference server limits individual requests to 16 MiB, caps resumed
  packs separately, bounds worker concurrency, and applies a socket timeout.
- Repository JSON CLI commands (`fsck`, `object`, `migrate-v3`, `fetch`, `push`)
  emit plain JSON; the shared console no longer forces ANSI color, so piped or
  redirected output is machine-readable and honors `NO_COLOR`.
- Local CAS ref updates take an exclusive lock, making the compare-and-swap
  atomic (no lost updates) and directory writes are fsynced for durability.
- V2 migration is fail-closed: a source that fails integrity (or a requested
  signature) is refused unless `--allow-unverified` / `strict=False` is passed.
- Object envelope headers are bound to exactly `{encoding, schema, type}`, and
  `Run.save` to a repository target rejects `.tine` signing/draft options rather
  than silently ignoring them.
- Audit rows use a serialized HMAC chain and authenticated external head;
  startup and `verify_audit_chain` detect modification, reordering, and
  truncation. Legacy rows require explicit trust-on-migration and remain marked
  unverified. Read operations are audited.
- OIDC ships a real `JWTVerifier` with RS256/ES256 algorithm/key binding, JWKS,
  issuer/audience/authorized-party/time validation, critical-header rejection,
  and bounded discovery documents.
- Credential redaction catches vendor-prefixed and header-style key names
  (`OPENAI_API_KEY`, `x-api-key`, …) while preserving numeric usage counters.
- The OTel importer parses extracted spans or complete OTLP/JSON exports
  (camelCase/snake_case keys and typed `AnyValue` attributes); JSONL/framework
  importers accept ISO-8601 timestamps and
  list-shaped messages without crashing or corrupting data.
- Billing: tiered context multipliers apply only the highest matching tier
  (no compounding); OpenAI-compatible top-level cache tokens
  (`prompt_cache_hit_tokens`) are billed at the cache rate, not as fresh input.
- All client control-plane JSON is streamed under a 1 MiB cap. Resumable upload
  offsets must advance, loops are bounded, upload IDs are validated, per-upload
  locks are released, and stale partial uploads are reaped. Agent web fetches
  also enforce their policy body cap during streaming rather than after buffering.
- Raw and structured redaction covers Basic/Cookie credentials in header lines,
  arrays, pairs, and HAR-style `{name, value}` records. Large trace integers are
  string-preserved, malformed JSONL records are skipped per line, and imported
  parents/causal links are ordered before recording.
- Kernel errors now wrap oversized integer literals; v2 migration parses the
  verified bytes only; OIDC rejects unsupported critical headers; pack manifests
  require an integer version; repository descriptors are bounded and versioned.
- The signed catalog was reverified and rotated to a retained release key. It
  adds Gemini 3.5 Flash and GLM-5.2, maps current DeepSeek compatibility aliases
  to V4 Flash, distinguishes Gemini audio/cache dimensions and exact service
  rates, and updates current Mistral model-card sources.
- Live traces retain cost and latency, causal forks retain causal ancestors, and
  semantic diff includes artifacts and evaluation scores.

### Architecture and compatibility

- Every production Python module is capped at 250 physical lines; CI also caps
  the complete trusted kernel and rejects dependency-layer violations.
- `Run.save/load` can wrap repositories while legacy file behavior stays v2.
- The enterprise claim applies to the repository and extension seams. The
  bundled bounded WSGI server targets development and small self-hosted use,
  not turnkey HA, hosted SaaS, or billing/payment services.

## 0.2.1 — 2026-07-15

Provider-neutral usage and cost accounting without changing `.tine` v2.

### Added

- Public `Usage`, `BillingResult`, `RateCard`, and `PricingCatalog` records with
  Decimal arithmetic, effective dates, cache/reasoning dimensions, context
  thresholds, service modifiers, currencies, and explicit complete/partial/
  unknown/unmetered states.
- Signed bundled pricing snapshot plus explicit `tine pricing list`, `show`,
  `check`, and `update`; local discount/infrastructure overlays remain separate
  from the signed upstream snapshot. No inference-time network lookup.
- Provider-scoped cards for OpenAI, Anthropic, Kimi, DeepSeek, Gemini,
  Grok/xAI, GLM/Z.AI, Qwen, Groq, Together, Mistral/Ministral, and Hermes. An
  unknown exact price is visible and never inherits another provider's rate.
- Digest-covered catalog signature/hash provenance, rate-card selection, and
  calculation inputs; the existing `cost` field is the known subtotal.
- Strict cost-completeness budgets through `Budget(strict_cost=True)`.

### Changed

- Native OpenAI models use Responses API semantics; compatible services retain
  a separate Chat Completions transport.
- Anthropic retains cache buckets and distinguishes early non-billable from
  midstream billable refusals. Kimi uses its current endpoint/default and
  preserves reasoning continuation. Google and Ollama retain usage/timing.
- Every invocation is recorded even for tool-only output, refusal, or a raised
  error carrying billable partial output.
- Credential redaction is typed/path-aware so numeric usage counters survive.

## 0.2.0 — 2026-06-29

Format `.tine` v2 plus six coordinated features. Reading v1 stays fully
supported; the public Python API only grows.

### Added

- **Format migration** — `FORMAT_VERSION` 2 with a pure migration registry.
  `Run.load` auto-migrates v1 in memory (never rewriting the file); re-saving
  upgrades to v2. New `tine migrate` (dry-run by default; verifies the source
  first). Also best-effort imports the legacy **0.1.0 linear format** (recomputes
  step ids). New `golden_v2.tine` / `golden_signed_v2.tine` / `golden_v0_linear.tine`
  fixtures.
- **Run tags + search** — `Run.tags` (+ `add_tag`/`remove_tag`/`has_tag`),
  persisted at `metadata.tags` outside the digest so re-tagging never changes a
  digest/signature. New `tine tag` / `tine search` (query DSL) / `tine reindex`
  and tag/model/status/cost/date/text filters on `tine ls`, backed by a
  rebuildable `.tine_runs/index.json` sidecar.
- **Cost + budget** — per-step `usage` tokens, `Run.total_tokens`,
  `Run.cost_breakdown()`, and `Run.set_budget(...)` enforced in the agent loop
  (`stop`/`raise`). New `tine cost`. (Serialized keys avoid "token" to dodge
  redaction; budgets live in `manifest.budget`, inside the digest.)
- **Streaming autosave** — atomic, crash-safe draft checkpoints with AND-throttle
  for long runs; native `Agent` and harnesses both flush a clean final artifact.
  Drafts carry a top-level `draft` flag inside the digest. `tine run --autosave`.
- **Signing (`tine-sig/1`)** — HMAC-SHA256 (stdlib) and optional Ed25519
  (`opentine[crypto]`). `Run.save(sign_key=...)`, `Run.verify_signature(...)`,
  `tine sign` / `tine keygen` / fail-closed `tine verify --key-*`/`--pubkey`.
  The signature commits to content (not the stored digest) and excludes mutable
  metadata so tags/budget/autosave edits don't break it.
- **Field-level diff** — `Run.diff` now populates `changed` via lineage-position
  alignment with `StepChange`/`FieldDelta`; `tine diff` renders per-field
  before/after, including cost/usage drift between same-id steps.

### Changed

- `FORMAT_VERSION` 1 → 2. `RunDiff.changed` is now `list[StepChange]`.
  `IntegrityResult` gains a `draft` field. Saves are now atomic.

### Compatibility

- 0.2 reads and migrates v1. **0.1.x cannot read v2**, and re-saving a v1 file
  upgrades it to v2 (one-way). HMAC signing needs no extra; Ed25519 needs
  `pip install "opentine[crypto]"`.

## 0.1.1 — 2026-06-25

- Ollama adapter now detects tool-calling capability via `/api/show` (cached) so
  `Ollama(...).supports_tools` is accurate. Agents with tools on a model that
  does not support them (e.g. `gemma3`, `codellama`, `phi4`, `deepseek-r1`) now
  run without tools and record a note in `run.metadata["warnings"]` instead of
  failing with an opaque Ollama `400`.
- OpenAI adapter token pricing is now configurable
  (`input_cost_per_mtok` / `output_cost_per_mtok`). Local OpenAI-compatible
  wrappers (`LMStudio`, `VLLM`, `Unsloth`, `LlamaCpp`, `LocalAI`, `Jan`) report
  `$0` cost by default instead of inheriting gpt-4o pricing.
- Removed the unused `msgspec` runtime dependency.
- Added a `mcp` optional extra (`pip install opentine[mcp]`) for the MCP server.
- Fixed the broken README logo (now a committed `docs/assets/opentine-logo.svg`).
- CI now runs `twine check` and uploads the built wheel/sdist as a downloadable
  artifact on every run; tagged releases carry `SHA256SUMS` plus a verifiable
  build-provenance attestation (`gh attestation verify`).

## 0.1.0

Initial public beta for the current 0.1.x surface.

- Added explicit `.tine` integrity verification through `Run.verify_integrity(...)` and `tine verify`.
- Added golden v1 `.tine` fixture coverage for load, save, fork, and diff behavior.
- Added security regression coverage for redaction, digest failure, path escape, symlink escape, private-network blocking, shell/Python denial, environment isolation, and output caps.
- Added a CI-sized graph performance smoke test for save, load, fork, and diff.
- Added wheel smoke testing for installed-package import, `tine --help`, and `tine verify`.
- Replaced PyPI publishing automation with a GitHub release artifact workflow that builds sdist/wheel, checks metadata, generates `SHA256SUMS`, and attaches artifacts to tagged GitHub releases.
- Documented the security model, current `.tine` v1 format policy, troubleshooting notes, and support policy.

Known scope:

- Package metadata remains `Development Status :: 4 - Beta`.
- `.tine` compatibility is current v1 only; migrations are future work.
- Artifact checksums are provided, but HMAC/signing and PyPI trusted publishing are not part of this pass.
