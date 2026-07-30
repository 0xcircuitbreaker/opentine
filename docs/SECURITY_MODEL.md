# OpenTine Security Model

OpenTine is local-first provenance tooling. It records agent activity and can invoke tools or external harnesses, but those execution paths are intentionally gated by explicit policies.

## Default Posture

- Filesystem tools are constrained to configured roots, use `Path.relative_to` checks, deny symlinks by default, cap file size, and require explicit write roots.
- Network tools allow HTTPS by default, block private, loopback, link-local,
  reserved, and multicast hosts unless policy opts in, and stream responses under
  the configured body-size limit. Visible-text extraction is linear on malformed
  markup rather than applying unbounded backtracking expressions.
- Shell execution is disabled unless a `ShellPolicy` enables it. Enabled shell calls are parsed to argv arrays, executable allowlists can be enforced, environment inheritance is off by default, and output is capped.
- Python execution is disabled unless a `PythonPolicy` enables it. Enabled snippets run in a subprocess with a scrubbed environment by default and capped output.
- External CLI harnesses do not inherit the parent environment by default.
  `--harness-login-env` passes only login/config variables plus explicitly allowed
  names. Harness subprocesses have configurable wall-time, total-output, line-size,
  and parsed-event ceilings and clean up their owned process group or Job Object on
  completion and errors. This is resource containment, not an OS sandbox.

Built-in tool schemas expose only task inputs. Filesystem roots, network and
execution policies, timeouts, allowlists, and output ceilings are host-owned
configuration; undeclared model arguments are rejected at runtime. Registering
`shell.run` or `python.execute` directly therefore remains disabled. To enable
one, register a small application wrapper that binds an explicit policy instead
of accepting policy values from a model call.

Configured model/provider endpoints are trusted peers. Native SDKs and the
OpenAI-compatible transport may buffer or decompress complete responses or
individual stream events before OpenTine applies its retained-content limits.
An arbitrary or attacker-controlled `base_url` can therefore exhaust client
memory. Compatible endpoints disable ambient proxies and redirects, but those
controls are not a response-size guarantee.

## Redaction

Saved v2 files and v3 structured objects use typed/path-aware credential names
such as `api_key`, `accessToken`, `passwords`, `client_secret`, scoped
authorization/cookie fields, and private keys. Acronym/camel/plural forms and
bare-token line/pair/HAR header captures are normalized. A numeric counter such
as `input_tokens` or a numeric direct field named `token` is retained.
Credential-shaped UTF-8 assignments, bearer values, PEM private keys, and common
header captures are also scrubbed from raw v3 blobs.

A PEM private-key marker without a matching end marker is redacted by scanning
forward for key material only, so the scan removes the key without taking
surrounding diagnostics with it. When the marker's own line also carries text
that is not key material, only a single leading base64 run of at least 40
characters is consumed and the rest of the line is preserved; a shorter run is
prose, not a key, and nothing after the marker is removed. Scanning past that
line stops at the first blank or non-base64 line. A PEM block embedded inside
JSON is still redacted even though its line breaks are `\n` escape sequences, and
a truncated passphrase-encrypted key is redacted through its RFC 1421
`Proc-Type`/`DEK-Info` headers and the single blank line that closes them, rather
than stopping at that blank line and emitting the body verbatim.

V3 redaction happens before canonicalization and hashing, so an object ID always
identifies the redacted bytes actually stored. V2 keeps its released identity
semantics; see the documented limitation in `TINE_FORMAT.md`.

This is a best-effort safety layer, not a proof that arbitrary sensitive data cannot appear in free-form model text or tool output. Review artifacts before sharing them outside a trusted boundary.

`Repo.put(..., redact=False)` is a deliberate low-level escape hatch for already
sanitized or byte-exact data. V2 migration uses it for the required legacy blob,
which preserves the original bytes and may therefore preserve secrets. Treat
legacy blobs as sensitive and do not push them before review.

## Integrity (checksum)

`Run.save()` writes a SHA-256 digest to `metadata.integrity`. `Run.verify_integrity(...)` and `tine verify <run.tine>` recompute the digest and report missing, malformed, or mismatched metadata.

The digest covers the redacted artifact body outside the `metadata` object. It detects accidental corruption and many body edits, but it is **not** tamper-proof: anyone who can edit the file can recompute the digest. For tamper-evidence against an adversary, sign the artifact.

## Signing (`tine-sig/1`)

`tine sign` / `Run.save(sign_key=...)` adds a signature at `metadata.integrity.signature`. It commits to a single canonical *signed view* recomputed from the artifact's content — not to the stored digest — so a body edit plus a digest rewrite still fails verification. The signed boundary (see `TINE_FORMAT.md`) covers the whole body plus an **allowlist** of exactly ten metadata keys: `model_info`, `system_prompt`, `user_prompt`, `forked_from`, `fork_point`, `warnings`, `replay`, `context`, `next_harness`, and `migration`.

**Every other metadata key is unauthenticated.** Mutable and derived fields
(`tags`, `budget_state`, `autosave`) sit outside the allowlist deliberately, so
that changing one of them cannot turn a valid signature into a *mismatch* — but
so does every other key the allowlist does not name, including any key an
application sets and `fork_reason`, which OpenTine's own MCP fork tool writes.
The integrity digest does not cover them either: it excludes the whole
`metadata` object. A metadata key outside the allowlist is therefore protected by
neither mechanism, and editing one leaves both `Run.verify_integrity` and
`Run.verify_signature` reporting success. Application data that has to be
authenticated belongs in the artifact body — a step record or `manifest` — not in
a bare `metadata` key.

The `tags` exclusion is about verification, not persistence. Signing is always an explicit act: any plain re-save — including `tine tag`, which rewrites the artifact — **removes** the signature block rather than re-attaching a signature the current writer did not produce. `tine tag` says so when it does this. Re-run `tine sign` afterwards, and treat "no signature" as a state to check for, not merely "mismatch".

- **HMAC-SHA256** (stdlib, no extra dependency): shared-secret authenticity. Keys shorter than 16 bytes are refused. Keys come from `--key-env` or `--key-file`; they are never written into the artifact.
- **Ed25519**: public-key signatures. Verifying against the artifact's own embedded key is reported as `verified-tofu` (trust-on-first-use) — the key is self-asserted, not authenticated.
- `tine verify` is **fail-closed**: supplying any key (`--key-env`/`--key-file`/`--pubkey`), `--trust-embedded-key`, or `--require-signature` makes an unsigned, unsupported, or mismatched artifact exit non-zero. `--trust-embedded-key` is itself a request to check authenticity, so it arms the check exactly as a supplied key does.

What a valid signature **does** prove: the signed body + allowlisted metadata have not changed since signing by a holder of the key.

What it does **not** prove:
- HMAC is symmetric — it gives intra-group authenticity, **not** non-repudiation; anyone with the shared key could have produced it.
- The `signer` label and an embedded Ed25519 key are self-asserted; OpenTine has no key→identity binding, PKI, or revocation.
- A *stripped* signature is byte-indistinguishable from a never-signed artifact, so the file alone cannot prove it *should* be signed — establish that expectation out of band.
- It does not prove the artifact was integrity-clean when it was signed. `tine sign` refuses an artifact whose stored digest does not match its body, but `--force` waives that refusal, so a signature records what the signer accepted rather than that the signer checked it.
- Signing provides no confidentiality (artifacts are not encrypted).

## V3 repository and remote

The v3 kernel recomputes typed object IDs, rejects non-canonical envelopes,
validates typed links, and detects missing links/self-links. Deep `fsck` also
checks refs and event cycles. Shallow history is explicit rather than treated as
verified local content.

The reference remote requires TLS, with one exception that takes no opt-in: when
the base URL's host parses as a **literal loopback IP address** — anything in
`127.0.0.0/8`, `::1`, or an IPv4-mapped loopback address — a plain `http://` base
URL is accepted, and the client attaches its `Authorization: Bearer` header to
that plaintext connection. Any other host must use HTTPS or an explicit
insecure-development opt-in (`--allow-insecure` on the client, `--insecure-dev`
on the bundled server). The check is a literal IP parse, so the hostname
`localhost` is **not** recognized as loopback and an `http://localhost:...` base
URL is refused rather than allowed.

Authenticated repository clients disable implicit environment proxies,
preventing loopback bearer credentials from being forwarded through ambient
proxy variables. Bearer tokens are stored as hashes in memory and
compared in constant time. OIDC ships a `JWTVerifier` (RS256/ES256) that validates the JWS
signature against a JWKS plus issuer, audience, authorized party, expiry, and
not-before claims; unsupported critical headers and weak RSA keys are rejected.
Discovery is dependency-injected and HTTPS-only. A custom verifier can still be
injected, in which case the integrator is responsible for equivalent signature
and claim validation. Authorization combines a tenant namespace with
reader/writer/admin roles.

Installed objects are AES-GCM encrypted at rest with a per-tenant key derived
from the configured local master key and the tenant as associated data. A
resumable upload is stored as independently authenticated, tenant-bound encrypted
frames until verification and installation; its directories/files are also
restricted to mode 0700/0600 on POSIX, and stale uploads are reaped. Legacy
`TINEAES1` ciphertext remains readable. The reference server requires a key
provider; production deployments should supply a KMS-backed provider and handle
rotation outside this minimal server. SQLite audit rows form a serialized
HMAC-SHA256 chain. An authenticated head stored outside SQLite detects end
truncation as well as interior modification, deletion, and reordering. The
reference app derives the audit key from its local KMS master. A custom
`KMSKeyProvider` must supply a stable external audit-key derivation callback (or
the app must receive `audit_key`) and construction fails closed otherwise; it
never silently writes a production audit key beside SQLite. Direct
`SQLiteBackend` development use creates a mode-0600 sidecar key and tightens
looser existing permissions. Unchained legacy rows are refused unless
`--migrate-legacy-audit` explicitly trusts the database. The resulting chain is
reported as `legacy-unverified`, not cryptographically verified. Audit rows
commit before the external anchor advances; an anchor exactly one committed row
behind is forward-healed after interruption only when that row's HMAC verifies.
An OS-level lock spans database commit plus checkpoint update across processes.
Verification normally compares stable before/after database and authenticated-head
snapshots, taking the same exclusive lock only when a concurrent append requires a
consistent retry. Any other missing or mismatched anchor
requires `--reanchor-audit-head` with the already verified database head; the
migration flag cannot re-anchor a keyed chain. Chain verification is read-only.
Database triggers remain defense in depth. Local refs use exclusive lockfiles;
remote refs use SQLite `BEGIN IMMEDIATE` CAS. Run-moving refs are restricted to
run objects. Each audit append authenticates the current tail row and external
head in O(1); startup and explicit administrator verification stream and
authenticate the complete chain. Historical interior tampering therefore cannot
be laundered into a valid chain and is detected at startup or explicit verify,
though an append alone is not a full historical scan. Admission policies can
reject oversized or costly writes.

Control-plane ref discovery is capped at 1,000 refs. Annotation envelopes that
must be decoded to bind an annotation ref to its run are capped at 1 MiB each
and 8 MiB in aggregate, with a pre-read size check when the object-store adapter
supports it. Reference filesystem reads reject linked, non-regular, or
oversized encrypted object leaves before decryption.

The local authenticated-head file detects database-only rollback, but a host
administrator who restores both SQLite and that file to an earlier valid pair
can also restore a valid historical chain state. Deployments that must detect
coordinated full-host rollback need a monotonic off-host checkpoint or a custom
externally anchored audit sink.

Client-side redaction enables authorized server-side indexing but is not
end-to-end encryption: an authorized server decrypts objects. Operators remain
responsible for TLS certificates, KMS/identity configuration, database backups,
retention policy, rate limiting, and host hardening.

The filesystem object write, metadata update, and audit append are not one
distributed transaction. An audit-sink failure is surfaced to the caller, but a
mutation may already have completed without an audit row; chain verification
authenticates the rows that exist, not the completeness of the operation log.
Deployments requiring atomic compliance logging should provide a transactional
storage/index/audit adapter or externally anchored audit sink.

The bundled server applies request/upload limits, bounded worker concurrency,
socket inactivity timeouts, and an absolute request deadline, but remains a reference WSGI
deployment rather than a
turnkey high-availability edge service.

## Artifacts you did not write are untrusted input

Everything above describes producing artifacts. Reading one somebody else
produced is a separate trust boundary. A `.tine` file received from elsewhere, a
fetched pack, and a blob holding a recorded model response are all
attacker-influenced input, so the readers are bounded rather than trusting, and
every bound a reader enforces is also enforced at write time — a rule applied on
one side only produces files that save cleanly and then fail every later load.

- **Size.** A `.tine` artifact must be a regular file of at most 256 MiB, read
  through a bounded read rather than a whole-file slurp.
- **Nesting.** One nesting bound, `MAX_JSON_DEPTH` = 512, is shared by the
  canonical encoder and the pre-parse structural scanner, so what a writer emits
  is exactly what a reader accepts. The redaction and canonicalization walks
  carry a separate bound, `MAX_CANONICAL_DEPTH` = 768, which refuses deeply
  nested or self-referential caller data before it can exhaust the stack.
- **Structure.** A pre-parse scan caps structural tokens relative to size before
  the JSON parser allocates anything: for `.tine` artifacts a floor of 200,000
  tokens, an absolute ceiling of 16,000,000, and between them one structural
  token per 4 bytes. Bounding density rather than size alone is what makes
  container amplification unprofitable, because a container costs about 2 bytes
  on disk and far more once materialized. Repository blobs are compact canonical
  JSON, where a structural token is exactly one byte, so they carry the same
  floor and ceiling at one token per byte; the writer applies the reader's budget
  to the same bytes, so a blob wide enough to save stays narrow enough to load.
- **Numbers.** An integer literal is capped at 4,096 digits, non-finite numbers
  (`NaN`, `Infinity`) are rejected, and duplicate object keys are refused rather
  than resolved last-wins — all three are parser differentials between
  implementations.
- **Unicode.** A string holding an unpaired UTF-16 surrogate has no UTF-8
  spelling at all, so no two readers would reconstruct it identically and neither
  the digest nor the canonical form can be computed over it. It is refused, with
  the offending field path named, on both the write and read sides.
- **Shape.** Fields the object validators leave open are read through explicit
  shape guards, so a present-but-wrong-typed field produces a typed refusal or a
  documented fallback rather than an `AttributeError` or `TypeError` raised from
  inside the loader — a crash on an object `fsck` calls healthy takes out every
  command at once. Run and step records are validated against the reader's own
  rules before a save is allowed to persist.
- **Byte budgets.** `diff`, `inspect` and context slicing bound both the size of
  each object they read and their aggregate source and output bytes, and refuse
  instead of reading unboundedly. Refs, shallow-boundary files and repository
  config are read under their own smaller caps.
- **Boundaries.** An object beyond a shallow clone's fetch boundary is a typed
  refusal naming the boundary, not a missing-object error.
- **Terminal output.** Text taken from an artifact has control bytes, C1 codes,
  and bidirectional formatting characters removed and console markup escaped
  before the CLI prints it, so a recorded model response cannot repaint or
  reorder your terminal.

These are containment bounds, not a guarantee that content which passes them is
safe to act on. Recorded model output remains untrusted text; see the non-goals
below.

## MCP server

`opentine.mcp_server` is a shipped entry point (the `mcp` extra) that hands a
model tools which read and mutate a repository. The run content the model reads
through those tools is untrusted: text recorded inside a run can address the
model directly, so every repository tool assumes its arguments may have been
chosen by whoever produced the run rather than by the operator.

- **Ref confinement.** MCP fork and resume may write only refs under
  `experiments/`. A fork's ref update is an unconditional overwrite, so any ref a
  model can write is a ref it can destroy; mainline (`heads/`), release gates
  (`promotions/`), labels (`tags/`) and remote-tracking refs stay operator-only.
  The namespace test runs on the canonical ref name, not on the caller's string,
  so it cannot disagree with the name that later reaches the filesystem, and the
  fully qualified `refs/experiments/...` form is still accepted.
- **Promotion is off by default.** `promote_run` is registered only when a host
  passes `allow_promotion=True` to `register_repository_tools`; the shipped
  server does not pass it, so the tool is not exposed. A promotion ref is a
  release gate — the compare-and-swap prevents an existing promotion being
  clobbered, but creating one is an operator decision, not a model's.
- **Attestation is a claim, not a signature.** Evaluation and attestation tools
  record a caller-supplied `signer` label and no cryptographic signature, with
  the same self-asserted-identity caveat as the signing section above.

A host that registers these tools should treat the repository itself as the
security boundary. A model holding the fork tool can create runs and consume
storage under `experiments/`, and the tools run with whatever filesystem access
the host process has.

## Known Non-Goals

- OpenTine does not sandbox arbitrary third-party CLI agents by itself.
- OpenTine does not guarantee that model output is safe to execute.
- OpenTine does not provide key distribution, identity binding, revocation, or multi-signature (`tine-sig/1` is single-signature).
- OpenTine does not currently provide encrypted `.tine` artifacts.
- The reference remote is not a hosted control plane, payment system, or a
  turnkey high-availability deployment.
