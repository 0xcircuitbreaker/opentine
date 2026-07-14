# Opentine Security Model

Opentine is local-first provenance tooling. It records agent activity and can invoke tools or external harnesses, but those execution paths are intentionally gated by explicit policies.

## Default Posture

- Filesystem tools are constrained to configured roots, use `Path.relative_to` checks, deny symlinks by default, cap file size, and require explicit write roots.
- Network tools allow HTTPS by default and block private, loopback, link-local, reserved, and multicast hosts unless policy opts in.
- Shell execution is disabled unless a `ShellPolicy` enables it. Enabled shell calls are parsed to argv arrays, executable allowlists can be enforced, environment inheritance is off by default, and output is capped.
- Python execution is disabled unless a `PythonPolicy` enables it. Enabled snippets run in a subprocess with a scrubbed environment by default and capped output.
- External CLI harnesses do not inherit the parent environment by default. `--harness-login-env` passes only login/config variables plus explicitly allowed names.

## Redaction

Saved v2 files and v3 structured objects use typed/path-aware credential names
such as `api_key`, `access_token`, `password`, `client_secret`, `authorization`,
and private keys. A numeric counter such as `input_tokens` or a numeric field
named `token` is retained. Credential-shaped UTF-8 assignments, bearer values,
and PEM private keys are scrubbed from raw v3 blobs.

V3 redaction happens before canonicalization and hashing, so an object ID always
identifies the redacted bytes actually stored. V2 keeps its released identity
semantics; see the documented limitation in `TINE_FORMAT.md`.

This is a best-effort safety layer, not a proof that arbitrary sensitive data cannot appear in free-form model text or tool output. Review artifacts before sharing them outside a trusted boundary.

## Integrity (checksum)

`Run.save()` writes a SHA-256 digest to `metadata.integrity`. `Run.verify_integrity(...)` and `tine verify <run.tine>` recompute the digest and report missing, malformed, or mismatched metadata.

The digest covers the redacted artifact body outside the `metadata` object. It detects accidental corruption and many body edits, but it is **not** tamper-proof: anyone who can edit the file can recompute the digest. For tamper-evidence against an adversary, sign the artifact.

## Signing (`tine-sig/1`)

`tine sign` / `Run.save(sign_key=...)` adds a signature at `metadata.integrity.signature`. It commits to a single canonical *signed view* recomputed from the artifact's content — not to the stored digest — so a body edit plus a digest rewrite still fails verification. The signed boundary (see `TINE_FORMAT.md`) covers the whole body plus an allowlist of authenticity-relevant metadata, and deliberately excludes mutable/derived fields (`tags`, `budget_state`, `autosave`) so ordinary edits don't break a valid signature.

- **HMAC-SHA256** (stdlib, no extra dependency): shared-secret authenticity. Keys shorter than 16 bytes are refused. Keys come from `--key-env` or `--key-file`; they are never written into the artifact.
- **Ed25519**: public-key signatures. Verifying against the artifact's own embedded key is reported as `verified-tofu` (trust-on-first-use) — the key is self-asserted, not authenticated.
- `tine verify` is **fail-closed**: supplying any key (`--key-env`/`--key-file`/`--pubkey`) or `--require-signature` makes an unsigned, unsupported, or mismatched artifact exit non-zero.

What a valid signature **does** prove: the signed body + allowlisted metadata have not changed since signing by a holder of the key.

What it does **not** prove:
- HMAC is symmetric — it gives intra-group authenticity, **not** non-repudiation; anyone with the shared key could have produced it.
- The `signer` label and an embedded Ed25519 key are self-asserted; opentine has no key→identity binding, PKI, or revocation.
- A *stripped* signature is byte-indistinguishable from a never-signed artifact, so the file alone cannot prove it *should* be signed — establish that expectation out of band.
- Signing provides no confidentiality (artifacts are not encrypted).

## V3 repository and remote

The v3 kernel recomputes typed object IDs, rejects non-canonical envelopes,
validates typed links, and detects missing links/self-links. Deep `fsck` also
checks refs and event cycles. Shallow history is explicit rather than treated as
verified local content.

The reference remote requires TLS unless an operator explicitly enables local
insecure development. Bearer tokens are stored as hashes in memory and compared
in constant time. OIDC ships a `JWTVerifier` (RS256/ES256) that
validates the JWS signature against a JWKS plus issuer, audience, and expiry; a
custom verifier can still be injected. Authorization combines a tenant namespace
with reader/writer/admin roles.

Objects are AES-GCM encrypted at rest with a per-tenant key derived from the
configured local master key and the tenant as associated data. Legacy
`TINEAES1` ciphertext remains readable. The reference server requires a key
provider; production deployments should supply
a KMS-backed provider and handle rotation outside this minimal server. SQLite
audit rows are hash-chained — each row commits to the previous row's hash, so any
modification, deletion, or reordering of an interior row is detectable via
`verify_audit_chain`. Database triggers remain as defense in depth, and
`audit_head` can be anchored out of band to also detect end-truncation. CAS ref
updates use an exclusive lock to prevent lost updates, and admission policies can
reject oversized/costly writes.

Client-side redaction enables authorized server-side indexing but is not
end-to-end encryption: an authorized server decrypts objects. Operators remain
responsible for TLS certificates, KMS/identity configuration, database backups,
retention policy, rate limiting, and host hardening.

The bundled server applies request/upload limits, bounded worker concurrency,
and socket timeouts, but remains a reference WSGI deployment rather than a
turnkey high-availability edge service.

## Known Non-Goals

- Opentine does not sandbox arbitrary third-party CLI agents by itself.
- Opentine does not guarantee that model output is safe to execute.
- Opentine does not provide key distribution, identity binding, revocation, or multi-signature (`tine-sig/1` is single-signature).
- Opentine does not currently provide encrypted `.tine` artifacts.
- The reference remote is not a hosted control plane, payment system, or a
  turnkey high-availability deployment.
