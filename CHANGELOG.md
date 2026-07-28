# Changelog

## 0.3.0 — 2026-07-20

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
  bounded pack download, resumable pack upload, tenant-scoped RBAC, static-token/OIDC seams,
  encrypted filesystem objects, SQLite metadata, hash-chained audit records, and
  pluggable storage/index/identity/authz/key/audit/retention/admission policies.
- CLI commands: `init`, `fsck`, `repo-log`, `object`, `pack`, `migrate-v3`,
  `fetch`, `push`, `clone`, and `serve`.

### Added (provider and harness coverage)

- Every hosted OpenAI-compatible adapter now requests usage accounting on
  streams. GLM (both the international and China endpoints), Together, Mistral,
  Ministral and Hermes previously sent no `stream_options.include_usage`, so a
  streamed call returned no token counts and priced as `unknown` — reporting
  $0.00 for real spend.
- `tine pricing update` installs to the path the loader actually reads. It
  hard-coded `~/.config` while `load_catalogs` honours `XDG_CONFIG_HOME`, so
  under a non-default config home the update reported success and changed no
  prices.
- Harness presets are table-driven (`opentine/harnesses/_presets.py`), so
  supporting another terminal agent costs one row rather than a subclass. Adds
  `grok` (xAI Grok Build, `grok exec`) and `gemini` (Gemini CLI, `gemini -p`).
- `docs/pricing-overlay-claude-5.json` prices `claude-opus-5`,
  `claude-mythos-5`, and `claude-haiku-4-5` ahead of the next signed catalog
  release; see PRICING.md.

### Fixed (final pre-release audit)

- An OIDC token carrying no roles claim now grants no roles instead of silently
  defaulting to `reader`. A misconfigured issuer, or one that stops emitting the
  claim, previously conferred read access to every run in the tenant. Operators
  who relied on the old behaviour can pass `default_roles=("reader",)`.
- The remote's SQLite metadata database and its WAL/shm siblings are created
  `0600`. sqlite3 applied the process umask — typically world-readable — while
  every other file the server writes was already hardened.
- `tine keygen --out` and `tine sign --save` refuse to overwrite an existing file
  without `--force`. Clobbering a private key destroys the only copy of a signing
  identity and makes every artifact it signed unverifiable.
- `tine ls`, `tine search`, and `tine reindex` report an over-cap runs directory
  as an error naming the limit and the directory, rather than an interpreter
  traceback.
- An effective-date string honours its UTC offset. Truncating to the first ten
  characters dropped it, so a timestamp already into the next day in UTC resolved
  to the previous day's rate card.
- Free-text cost scraping requires a currency marker, so an agent writing
  "cost: 500" about an approach it was weighing no longer books $500 to the run.
- Credential redaction no longer leaks on two common shapes. A v2 assignment
  whose value contains a colon (`api_key=sk-proj:abc`) was split on the colon,
  which buried the credential name in the label and stored the secret in
  cleartext; the separator is now chosen by position. In v3 blobs, a credential
  preceded by a dash — a `git diff` removal line for a `.env` file, or a captured
  `--api-key=…` argv — was never matched. Name matching stays linear.
- A run long enough to save is again long enough to load. The reader enforced a
  fixed structural-token cap that the writer did not, so runs of roughly 20k
  steps were persisted and then permanently unreadable. The bound now scales with
  artifact size, keeping the container-amplification guard intact.
- Updating a ref no longer stages through a filename that is another ref's guard
  lock (`x` staged as `x.new.lock`, which is ref `x.new`'s lock). The old name
  made a sibling update fail, then deleted the lock a live writer still held,
  defeating the compare-and-swap.
- `tine migrate-v3` reports its fail-closed refusal on a tampered artifact as an
  error instead of an unhandled traceback.
- `inspect(resolve_blobs=True)` no longer auto-resolves `legacy_blob`, the one
  deliberately unredacted blob, which the MCP `inspect_object` tool returned to a
  model by default. It remains reachable by its own object id.
- MCP `fork_run_v3`/`resume_run_v3` may only write `experiments/*`. Their ref
  update is an unconditional overwrite, so mainline, promotion, tag and
  remote-tracking refs are no longer reachable from untrusted run content.
- Harness-reported `duration_ms` is converted to seconds rather than stored
  verbatim, which inflated durations 1000x and could trip a duration budget.
- `tine tag` warns when re-saving removes a signature; `SECURITY_MODEL.md` no
  longer implies the signature survives an ordinary edit.
- The OpenRouter adapter requests usage accounting; because it is priced from
  provider-reported cost with no rate-card fallback, streamed calls previously
  always reported `unknown` and $0.00.
- Adapter billing tests derive the expected charge from the effective rate card
  instead of freezing a promotional rate that expired on 2026-07-23.

### Fixed (post-audit hardening)

- Billing arithmetic now runs in a fixed Decimal context, independent of caller
  precision, rounding, or traps. Compatibility totals accumulate exact pinned
  subtotals, terminal model calls cannot escape budget enforcement, and tool
  latency contributes to wall-duration budgets.
- Provider accounting now handles xAI's exclusive reasoning tokens, cumulative
  stream usage, exact charged-cost ticks, and observed Priority tier; OpenRouter
  reported account/upstream costs; Groq final stream usage; Anthropic thinking
  tokens; OpenAI cache writes and observed Priority tier; canonical model aliases;
  and top-level/nullable cache counters without silently claiming completeness.
- The first public catalog trust anchor is the retained `r3` key; unpublished
  pre-release `r1`/`r2` keys with no durable custody were retired. The snapshot
  ends stale DeepSeek alias pricing when V4 launched and prices Mistral reasoning
  at its documented output rate.
- Deep graphs use iterative ancestry and fixed-size structural diff keys. CLI
  rendering strips terminal control sequences, cached replay cannot derive paths
  from artifact IDs, filesystem tools reject special files, trace payload types
  fail before storage, and DuckDuckGo HTML parsing is linear and bounded.

- Canonical JSON now rejects integers beyond the exactly representable range
  (±(2**53−1)) instead of silently coercing them to a float, which could collide
  two distinct values onto one object id and corrupt stored values.
- Pack transfer and decompression are bounded (maximum 256 MiB), reject trailing
  compressed data, and stream client downloads under the same cap, so a zlib bomb
  from an untrusted remote or authenticated writer cannot grow memory without
  bound. The reference server limits individual requests to 16 MiB, caps resumed
  packs separately, bounds worker concurrency, and applies inactivity plus absolute
  request timeouts.
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
  unverified. Repository read operations are audited; verification itself is read-only.
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
- All client control-plane JSON is streamed under a 1 MiB raw-byte cap and
  non-identity content encodings are rejected, with a wall-clock deadline that
  includes response headers. Resumable upload offsets must advance, loops are
  bounded, upload IDs are validated, staging uses encrypted tenant-bound frames
  plus private POSIX modes, per-upload locks are released, and stale partial
  uploads are reaped. Agent web fetches pin validated DNS answers, ignore implicit
  proxies, and enforce whole-response time and body limits.
- Raw and structured redaction covers Basic/Cookie credentials in header lines,
  arrays, pairs, and HAR-style `{name, value}` records. Large trace integers are
  string-preserved, malformed JSONL records are skipped per line, and imported
  parents/causal links are ordered before recording.
- Trace bulk import now writes one final run snapshot in linear graph work and
  preflights a 3,000-event run ceiling before writing blobs. Repository search
  and object inspection verify data under explicit object, source-byte, and
  rendered-output caps so deduplicated references cannot amplify memory use.
- Kernel errors now wrap oversized integer literals; v2 migration parses the
  verified bytes only; OIDC rejects unsupported critical headers; pack manifests
  require an integer version; repository descriptors are bounded and versioned.
- The signed catalog was reverified and rotated to a retained release key. It
  adds Kimi K3, Gemini 3.5 Flash, and GLM-5.2, maps current DeepSeek compatibility aliases
  to V4 Flash, distinguishes Gemini audio/cache dimensions and exact service
  rates, applies xAI's >200K Grok 4.5/4.3 prices, removes an unsafe `qwen-plus`
  cross-model alias, corrects Together's Llama 3.3 effective date, removes its
  deprecated Llama 3.1 cross-model alias, uses Mistral's canonical API IDs,
  splits GPT-4o's historical price transitions, and applies Anthropic's reported
  US inference geography multiplier. Qwen3.7-Max records its limited promotion,
  automatic-cache rate, and explicit cache creation/hit rates separately. Kimi
  K3 is the current default with its reasoning continuation and official
  $3/$0.30/$15 rates; Kimi Batch and Groq service tiers use exact rates, invalid provider aliases are
  removed, and tier-scoped Groq shutdown dates are recorded without suppressing
  enterprise committed-spend billing.
- Live traces retain cost and latency, causal forks retain causal ancestors, and
  semantic diff includes artifacts and evaluation scores.
- Production KMS adapters can provide external audit-key derivation and the
  reference app fails closed when neither that nor an explicit key exists.
  Audit rows commit before their authenticated anchor, one-step interrupted
  anchors heal safely, arbitrary recovery requires an exact dedicated re-anchor
  value, legacy migrations report `legacy-unverified`, and verification is
  read-only. Existing local audit-key sidecars are tightened to mode 0600.
- Scalar service-tier modifiers reject negative and non-finite values. Partial
  uploads survive transient short reads while terminal checksum/size failures
  are removed, pending-upload limits run before admission accounting, and push
  rejects malformed completion metadata. Credential assignment redaction is
  linear on delimiter-heavy input, truncated private-key captures cannot trigger
  quadratic scans, and benign credential-label prose is preserved while
  authentication header labels always fail closed.
- Search-provider responses are streamed under a fixed body cap with compressed
  payloads and redirects refused. Release metadata checks invoke Twine through
  the interpreter consistently in CI and tag-publish workflows.
- Enabled shell and Python tools drain child pipes continuously while retaining
  only a bounded prefix, clean up descendant processes after every execution,
  and use Windows Job Objects when available.
- Audit append authenticates the current chain tail before a one-step checkpoint
  heal. A cross-process file lock spans the SQLite commit and external anchor
  update. Verification uses stable optimistic snapshots and retries under that
  lock only across concurrent writes, preventing forged-row laundering and
  commit/checkpoint races without starving writers.
- Timed-out shell and Python tools terminate the spawned process tree, retain
  bounded partial diagnostics, and reserve output space for stderr. Run-moving
  refs (`heads`, `experiments`, `promotions`) and attestation targets are
  type-checked as runs; `fsck`, local operations, and the remote enforce the same
  rule while tags may still identify any immutable object.
- Repository CLI object-read failures now produce concise stderr messages rather
  than tracebacks, search rejects non-string queries explicitly, header redaction
  has no prose-shaped bypass, and a truncated PEM capture preserves later text
  only after a clear paragraph boundary.
- Stable audit verification uses an optimistic database/anchor snapshot and
  takes the exclusive cross-process lock only when a concurrent append requires
  a consistent retry, preventing hot admin verification from starving writers.
- Source distributions use an explicit allowlist, and CI/publish gates require
  both source and wheel archives to match their tracked-file inventories exactly,
  preventing globally ignored local agent/editor state from entering a release.
- Release automation now tracks and enforces the hashed dependency lock, pins
  the build backend, uv, and GitHub Actions by immutable versions/commits, builds
  the wheel from the validated sdist, and reuses that one artifact pair for an
  attested GitHub release and OIDC PyPI Trusted Publishing. Only the protected
  `pypi` environment's publish job receives an identity-token permission.
- External process harnesses now fail closed under configurable time, output,
  line-size, and parsed-event ceilings and clean up their owned process group or
  Job Object on every exit path. Git code capture streams under a 16 MiB ceiling;
  untracked paths mark the worktree dirty and make capture incompleteness explicit.
- Dependency floors exclude vulnerable cryptography wheels (`>=48.0.1`),
  Anthropic SDK releases (`>=0.87`), and MCP SDK releases. The OpenAI-compatible
  extra starts at `openai>=1.75.0`, the first SDK release that supports both the
  Responses API and its service-tier field. The MCP extra stays
  on the supported v1 line (`>=1.28.1,<2`) until OpenTine adopts its breaking v2 API.
  The development floor also excludes pytest's vulnerable tmpdir handling
  (`pytest>=9.0.3`).
- Authenticated repository clients ignore implicit environment proxies so a
  loopback development bearer token cannot be forwarded through `HTTP_PROXY`.
  Web-result text extraction is linear on malformed markup, and structured
  redaction recognizes camel/acronym/plural/scoped credential names plus bare
  token header pairs while retaining numeric token counters.
- Qwen streams explicitly request final usage and retain explicit-cache billing
  tiers. Trace import accounting counts repeated/empty containers incrementally,
  rejects expansion-prone non-JSON values, and charges skipped oversized JSONL
  records. Harnesses observe direct-parent exit independently of inherited pipe
  handles and close an escaped descendant's retained pipe after a short drain.
- Custom `OpenAI` base URLs now default to the provider identity
  `openai-compatible`, so a proxy or compatible service cannot silently inherit
  an OpenAI rate card merely by reusing an OpenAI model name. Explicit provider
  and rate overrides remain authoritative.
- Shallow-boundary state is validated, cached, and capped across the repository;
  bounded object enumeration and negotiation no longer sort or parse an
  unbounded local tree. Pack creation and installation enforce the same global
  object and shallow-link ceilings before writing.
- Trace parent and causal resolution is qualified by `(trace_id, span_id)`.
  Duplicate spans and dependency cycles are rejected before recording, while
  unresolved partial-trace boundaries are retained explicitly instead of being
  silently rewritten. Ollama response/NDJSON parsing and OTLP `AnyValue`
  traversal now have body, line, depth, and cycle limits.
- OpenAI now defaults to GPT-5.6, Kimi accepts the official Moonshot credential
  names, and DeepSeek-compatible streams request final usage. Together's
  `reasoning` field and Mistral's list-shaped thinking/text blocks are retained,
  bounded, and replayed without duplicating private reasoning representations.
- `OpenAICompatible` accepts an exact hosted-gateway base with unknown billing
  by default; `LocalOpenAICompatible` accepts exact or conventional `/v1`
  local endpoints with unmetered billing by default. Named LM Studio, vLLM,
  Unsloth, llama.cpp/llama-cpp-python, LocalAI, Jan, SGLang, TGI, MLX-LM,
  NVIDIA NIM, TensorRT-LLM, and KoboldCpp presets remain compatible. Explicit
  local auth, tool suppression, final stream usage, and provider-specific
  request bodies are configurable without forwarding ambient OpenAI keys,
  proxies, or redirects.
- Provider SDK retries are disabled so one recorded invocation represents one
  attempted provider request, and short-lived SDK clients close deterministically
  after complete and streamed responses. Missing provider tool-call IDs are
  normalized once and stored consistently in steps, transcripts, and tool results.
- The README now uses the official website mark, documents generic local runtime
  endpoints and their trust boundary, and no longer ships obsolete unreferenced
  animation assets in the source distribution.
- Compatibility imports no longer treat event-shaped legacy step IDs as trusted
  v3 identities; only provenance recovered from a verified v3 wrapper can reuse
  an event map. Repository association/evaluation/annotation scans, semantic
  source reads, and reflog-ordered ref updates now have explicit hard bounds and
  stable write guards.
- Remote ref discovery bounds annotation decoding, filesystem object reads reject
  linked or oversized leaves before decryption, resumable-upload reaping cannot
  race an active transfer, and push clients bind completion receipts to the exact
  pack ID and object count submitted. The signed catalog also corrects Grok 4.5
  cached input to the official $0.30/MTok rate.

### Architecture and compatibility

- Every production Python module is capped at 250 physical lines; CI also caps
  the complete trusted kernel and rejects dependency-layer violations.
- `Run.save/load` can wrap repositories while legacy file behavior stays v2.
- The enterprise claim applies to the repository and extension seams. The
  bundled bounded WSGI server targets development and small self-hosted use,
  not turnkey HA, hosted SaaS, or billing/payment services.

## 0.2.1 — Unpublished; folded into 0.3.0

The provider-neutral billing work was developed under version 0.2.1, but no
`v0.2.1` tag or PyPI distribution was published. The first public release to
contain these changes, including the subsequent audit hardening, is 0.3.0.

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
