# OpenTine Security Model

> The byte-level rules behind everything below — the signed views, domain
> prefixes, verdict vocabulary, and both canonical forms — are specified in
> **[SPEC.md](SPEC.md)**.

OpenTine is local-first provenance tooling. It records agent activity and can invoke tools or external harnesses, but those execution paths are intentionally gated by explicit policies.

## Default Posture

- Filesystem tools are constrained to configured roots, use `Path.relative_to` checks, deny symlinks by default, cap file size, and require explicit write roots. A write never lands inside a `.git` directory (any case, or a `.git` file), because git executes commands named in repository configuration and hooks; and never through a hard-linked file, whose other names need not be inside the root.
- Network tools allow HTTPS by default, block private, loopback, link-local,
  reserved, and multicast hosts unless policy opts in — including an IPv6 address
  that embeds one (NAT64 `64:ff9b::/96`, IPv4-compatible `::/96`, 6to4, IPv4-mapped)
  and deprecated site-local `fec0::/10` — and stream responses under
  the configured body-size limit. Visible-text extraction is linear on malformed
  markup rather than applying unbounded backtracking expressions.
- Shell execution is disabled unless a `ShellPolicy` enables it. Enabled shell calls are parsed to argv arrays, executable allowlists can be enforced, environment inheritance is off by default, and output is capped. **An allowlist decides which program starts, not what it does**: an allowlisted interpreter, test runner or build tool (`python`, `pytest`, `npm`, `make`) is arbitrary code execution by design. `git` is the one program whose arguments are checked: options and subcommands that run a command, inject configuration, or point git at another repository (`-c`, `--config-env`, `--git-dir`, `config`, `submodule`, `--upload-pack`, `rebase -x`, `grep -O`, …) are refused, and every git OpenTine starts — the shell tool's and `code_manifest`'s — runs with fsmonitor off and `safe.bareRepository=explicit`, so a bare repository assembled from ordinary file writes is never discovered.
- An inherited environment is scrubbed by name (`*KEY*`, `*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*_PWD`, `*PASS`, `*_PAT`, `*_DSN`, `*WEBHOOK*`, `*CONNECTION_STRING*`, `*PRIVATE*`, …) **and by value**: a variable holding a vendor token shape, a URL with a password, or a private key is dropped whatever it is called.
- Python execution is disabled unless a `PythonPolicy` enables it. Enabled snippets run in a subprocess with a scrubbed environment by default and capped output. The built-in tool provides only the `subprocess` isolation backend; a policy naming any other (`external`, `gvisor`) is refused rather than run unisolated.
- External CLI harnesses do not inherit the parent environment by default.
  `--harness-login-env` passes only login/config variables plus explicitly allowed
  names. Harness subprocesses have configurable wall-time, total-output, line-size,
  and parsed-event ceilings and clean up their owned process group or Job Object on
  completion and errors. This is resource containment, not an OS sandbox.
  A text-mode agent CLI's stdout is the model's prose, so it is recorded as text:
  a JSON-shaped line is an event only when the command asks the CLI for JSON
  output (`--json`, `--output-format stream-json`, …), and a currency amount in
  free text is booked only for an operator-written command (`generic`, `pi`).

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

## Signing (`tine-sig/2`)

`tine sign` / `Run.save(sign_key=...)` adds a signature at `metadata.integrity.signature`. It commits to a single canonical *signed view* recomputed from the artifact's content — not to the stored digest — so a body edit plus a digest rewrite still fails verification. Which parts of the artifact that view covers is the **scheme**, recorded in the signature block:

- **`tine-sig/2`** (0.7.1+, what new signatures use): the whole body, the signature header, and **every `metadata` key except `metadata.integrity`** — including `tags`, `fork_reason`, and any key an application sets. `integrity` is excluded because it holds the signature block itself.
- **`tine-sig/1`** (0.3.0–0.7.0): the whole body, the header, and an **allowlist** of eleven metadata keys — `model_info`, `system_prompt`, `user_prompt`, `forked_from`, `fork_point`, `warnings`, `replay`, `context`, `next_harness`, `migration`, `fork`. Everything else in `metadata`, `tags` included, was unauthenticated: it could be rewritten and the signature still verified.

This build still verifies `tine-sig/1` blocks, unchanged and under their own narrower view. That scope is frozen rather than corrected: re-scoping it would flip genuine already-published signatures to a false *mismatch*. So a v1-signed artifact keeps its original guarantee — **re-sign it to gain v2's metadata coverage**. An older OpenTine reading a v2 artifact reports `unsupported signature scheme` rather than guessing.

The **integrity digest is unchanged and still excludes the whole `metadata` object.** That is not a hole in authenticity: the digest is unkeyed, so anyone who can edit the file can recompute it — it means "consistent", not "genuine". Authenticity of metadata comes from the v2 signature. On an *unsigned* artifact, a metadata edit still leaves `Run.verify_integrity` reporting success, exactly as a body edit with a recomputed digest does.

Signing is always an explicit act: any plain re-save — including `tine tag`, which rewrites the artifact — **removes** the signature block rather than re-attaching a signature the current writer did not produce. `tine tag` says so when it does this. Under v2 a re-tag is also a real content change, so an out-of-band edit to `tags` now reports *mismatch*: re-run `tine sign` afterwards, and treat "no signature" as a state to check for, not merely "mismatch".

- **HMAC-SHA256** (stdlib, no extra dependency): shared-secret authenticity. Keys shorter than 16 bytes are refused. Keys come from `--key-env` or `--key-file`; they are never written into the artifact.
- **Ed25519**: public-key signatures. Verifying against the artifact's own embedded key is reported as `verified-tofu` (trust-on-first-use) — the key is self-asserted, not authenticated.
- `tine verify` is **fail-closed**: supplying any key (`--key-env`/`--key-file`/`--pubkey`), `--trust-embedded-key`, or `--require-signature` makes an unsigned, unsupported, or mismatched artifact exit non-zero. `--trust-embedded-key` is itself a request to check authenticity, so it arms the check exactly as a supplied key does.

What a valid signature **does** prove: the signed view for the block's own scheme — the body plus all metadata under `tine-sig/2`, the body plus the allowlist under `tine-sig/1` — has not changed since signing by a holder of the key.

What it does **not** prove:
- HMAC is symmetric — it gives intra-group authenticity, **not** non-repudiation; anyone with the shared key could have produced it.
- The `signer` label and an embedded Ed25519 key are self-asserted; OpenTine has no key→identity binding, PKI, or revocation.
- A *stripped* signature is byte-indistinguishable from a never-signed artifact, so the file alone cannot prove it *should* be signed — establish that expectation out of band.
- It does not prove the artifact was integrity-clean when it was signed. `tine sign` refuses an artifact whose stored digest does not match its body, but `--force` waives that refusal, so a signature records what the signer accepted rather than that the signer checked it.
- Signing provides no confidentiality (artifacts are not encrypted).

## Attestation signing (`tine-attest/1`)

A v3 `attestation` is the object that says *someone approved this run*. Through 0.8.1 its `signer` was a bare label: anyone who could write to the repository could write `signer: security-team`, and nothing could tell. From 0.9.0 an attestation can be **signed**, with the same algorithms, key flags and verdicts as artifact signing.

`tine attest` / `tine evaluate` / `Repo.attest(..., key=...)` store a signature block at the attestation payload's `signature` key. The block commits to a canonical *signed view* of the attestation, recomputed from the stored object at verification time:

- **covered:** every payload key except `signature` — `target_id` (which run), `claim` (what is asserted), `signer` (whose assertion), `evidence_ids` (what backs it), and any field a later writer adds — plus the signature header (`alg`, `key_id`, `scheme`, `signed_at`, `signer`). Editing the claim, retargeting the approval at another run, renaming the signer, adding or dropping evidence, or downgrading the algorithm all report **mismatch**.
- **excluded:** the signature `value` itself (it is what is being computed; the rest of the block is inside the view), and the object id and envelope. The oid is the digest of the stored payload *including* the signature, so it cannot be signed — and needs no coverage, because content addressing already makes payload → oid tamper-evident and the payload is signed in full.
- The body signed is the payload **as stored**, i.e. after `Repo.put`'s credential redaction, so a claim containing an `api_key` field is signed in the redacted form every reader sees.
- The domain-separation prefix (`opentine.attestation.v1:`) differs from the artifact prefix (`opentine.signature.v1:`), so no signature can be lifted between the two families, and the scheme string is inside the signed header, so a future `tine-attest/2` cannot be confused with a v1 message.

`tine repo-verify <attestation-oid | run-ref-or-oid>` checks one attestation, or every attestation targeting a run. It reports the **same verdicts** as `tine verify`: `verified`, `verified-tofu` (Ed25519 trust-on-first-use against the block's own embedded key — self-asserted, not authenticated), `unsigned`, `no-key`, `mismatch`, `error`. Only the first two are a pass. It is fail-closed in the same way: supplying any key (`--key-env`/`--key-file`/`--pubkey`), `--trust-embedded-key`, or `--require-signature` arms the check and exits non-zero unless every attestation verified; `--require-signature` also refuses a run carrying *no* attestation, because "nothing to check" is not a valid signature. With nothing armed the verb is a report and exits 0 — an unarmed check has verified nothing and must not look like it has.

Signing is **opt-in and additive**, and that is a compatibility guarantee, not a default: an attestation written without a key is byte-identical to what 0.3.0–0.8.1 wrote (`"signature": null`), keeps its object id, loads out of any released repository, `fsck`s clean, and verifies as **`unsigned`** — never as `verified`. `signed_at` is not auto-stamped: an attestation's oid stays a function of its content, so a timestamp is supplied deliberately (`Repo.attest(..., signed_at=...)`) rather than making every re-attestation a new object.

What a valid attestation signature proves: the target, claim, signer, evidence and header have not changed since a holder of the key signed them. What it does **not** prove is what artifact signing does not prove either — HMAC is symmetric (intra-group authenticity, not non-repudiation), the `signer` label and an embedded Ed25519 key are self-asserted with no key→identity binding, revocation or PKI, and a *stripped* signature is indistinguishable from a never-signed attestation, so "this repository's approvals must be signed" is an expectation to enforce out of band (`tine repo-verify --require-signature` is how you enforce it in CI).

**Gate on the claim, not on the run.** Unscoped, every attestation on the run must verify — so a single unsigned note from any writer blocks the gate, and a verified *rejection* passed exactly as an approval did, because the check never looked at what was signed. `--signer NAME` (repeatable) and `--claim JSON` (the attestation's claim must contain these keys with these values) select the attestations a gate is about; it then passes when at least one selected attestation verifies, and the others are reported but neither pass nor block it. Either flag arms the check. A release gate should be scoped: `tine repo-verify heads/main --pubkey release.pub --signer security-team --claim '{"result": "pass"}'`. Every row carries its `claim`.

**One signature, one object.** A signature block is accepted only in the exact form `tine attest` writes: the header keys, the lowercase-hex `value`, and — for Ed25519 — the lowercase-hex `public_key`, which must be the key that verified. An extra key, re-cased hex, or another embedded key is `error`/`mismatch`, so one signature cannot mint several attestation ids. `verify_attestation` (and `tine verify`'s library half) accepts exactly one of `hmac_key`, `public_key`, `trust_embedded`; given several, the block's own `alg` would pick which of the caller's keys is trusted.

MCP's `attest_run` and `evaluate_run` deliberately take **no** key options: an MCP client is acting on run content it just read, and untrusted text must not be able to sign as an operator. Signing is an operator-surface capability only.

## Fork identity (v2)

A run id read from an artifact is **untrusted input**, exactly like every other
field in a `.tine` file: the loader accepts any string as `run_id`, and an
attacker who supplies an artifact controls both the source id and every step id.
OpenTine never lets that string reach the filesystem verbatim. Every path it
derives from a run id is named by a digest — `runs_dir / f"{id}.tine"` — and a v2
fork id is a SHA-256 of the fork basis, so it is always 64 hex characters no
matter what the source artifact claims. A hostile run id such as `../owned`
therefore enters the id only as a hash input and yields a 64-hex fork id that
cannot steer a write outside the runs directory.

A v2 fork id identifies the *fork act*. It is derived from the source lineage,
the retained slice, the branch, the caller's declared intent, and a recorded
random nonce, and the basis is stored in `metadata.fork` so the fork can prove
its own id. `verify_fork_id(run)` re-derives the id from that record and returns
one of three verdicts:

- **`True`** — the id is exactly what the recorded lineage re-derives.
- **`False`** — a record is present but does not produce the id, so the record
  was edited after the fork.
- **`None`** — no verdict. There is no record to check (a pre-0.4.0 fork, a fork
  made with an explicit `new_run_id`, or a fork created inside a v3 repository,
  whose run object carries no record), or the record is versioned beyond this
  build.

`None` is an abstention and **must never be read as "valid"**. It is the verdict
for legacy artifacts and repository-created forks precisely so the check never
accuses old provenance of tampering, which also means it can never vouch for it. The check is
total on hostile input: a crafted `metadata.fork` (non-dict, bad `slice_size`,
over-deep nesting) yields `False` or `None`, never an exception, and editing the
record cannot forge a `True` verdict without a SHA-256 preimage.

`verify_fork_id` does **not** replace `Run.verify_integrity`. It re-derives the
id from the recorded basis alone and never reads the graph, so editing, renaming,
or removing retained steps — including the fork point — leaves its verdict
unchanged; only `verify_integrity` catches those edits. `verify_integrity`
covers the whole artifact body; treat the fork check as a provenance signal
layered on top of it, not a substitute. It is a provenance check, not an
authorization check — it never gates a write, and an artifact author can always
make their own artifact self-consistent.

## V3 repository and remote

The v3 kernel recomputes typed object IDs, rejects non-canonical envelopes,
validates typed links, and detects missing links/self-links. Deep `fsck` also
checks refs and event cycles. Shallow history is explicit rather than treated as
verified local content.

**Discovery.** `Repo.open` (and every `tine` verb's default `--repo .`) walks up
from the start directory to the nearest `.tine`. On POSIX, a repository found in
a *parent* directory that another user owns is refused (git's CVE-2022-24765
class): adopting a `.tine` planted in `/tmp` or a shared project root would sign
the planter's runs with your key and copy your runs into their store. A
directory you name, or the current one, is trusted as before; list others in
`OPENTINE_SAFE_DIRECTORIES` (`os.pathsep`-separated, `*` for all). Windows has
no owner to compare and is not checked. A bare repository (`tine init --bare
DIR`) opens at its own path.

**Run annotations.** A run's tags and metadata live in an annotation object
named by its `annotations/<digest>` ref. Unreferenced annotations are still read
— every clone has relied on it, since `fetch` names only the branch tip's — but
not one that a pack delivered for a run the repository *already held*: those are
recorded in `.tine/unadopted` at install time and skipped, because anyone
handing over a pack (or writing to a shared remote) could otherwise attach
"approved" tags to an untagged local run. `fetch` fast-forwards every
annotation ref the remote advertises, so a real update to an older run arrives
through the remote's refs.

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

Control-plane ref discovery is capped at 1,000 refs. An annotation ref is bound
to its run by the target the index recorded when the annotation was installed
and verified, so listing decodes nothing in the normal case; an annotation the
index has no record of (a custom index, an interrupted install) is still decoded
under a 1 MiB-each, 8 MiB-aggregate budget, with a pre-read size check when the
object-store adapter supports it. `update_ref` runs the same listing check with
the new ref included before committing, so no write can leave a tenant's
listing — and with it every fetch, clone and push — permanently refused.
Reference filesystem reads reject linked, non-regular, or oversized encrypted
object leaves before decryption.

An object can carry at most 1,000 associated annotations and attestations,
enforced at install before anything is written, so no writer can attach enough
of them to someone else's run to exceed the fetch traversal bound and make it
unfetchable. Two installs run concurrently, so the cap can be overshot by up to
one pack's worth; data already above it is not cleaned up. A request body is
read before a worker takes one of the server-wide install slots, so a slow
upload cannot hold them.

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
- **Terminal output.** Text taken from an artifact, repository, catalog or
  remote reply has control bytes, C1 codes, bidirectional formatting characters
  and invisible/format characters (zero-width, word joiner, BOM, line/paragraph
  separators, Unicode tags) removed and console markup escaped before the CLI
  prints it, so a recorded model response cannot repaint, reorder or hide text
  on your terminal. That includes error lines: an uncaught exception prints one
  sanitized `tine: <message>` line (`OPENTINE_DEBUG=1` restores the traceback),
  and MCP tool output and errors are cleaned the same way.
- **Imports.** `tine import` applies the `.tine` reader's structural-token budget
  to every whole document and every JSONL line before `json.loads`, and enforces
  its byte cap by bounded reads for every source — pipes, FIFOs, devices and
  stdin included.

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
- OpenTine does not provide key distribution, identity binding, revocation, or multi-signature (`tine-sig/2` is single-signature).
- OpenTine does not currently provide encrypted `.tine` artifacts.
- The reference remote is not a hosted control plane, payment system, or a
  turnkey high-availability deployment.
