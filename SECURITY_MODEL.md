# Opentine Security Model

Opentine is local-first provenance tooling. It records agent activity and can invoke tools or external harnesses, but those execution paths are intentionally gated by explicit policies.

## Default Posture

- Filesystem tools are constrained to configured roots, use `Path.relative_to` checks, deny symlinks by default, cap file size, and require explicit write roots.
- Network tools allow HTTPS by default and block private, loopback, link-local, reserved, and multicast hosts unless policy opts in.
- Shell execution is disabled unless a `ShellPolicy` enables it. Enabled shell calls are parsed to argv arrays, executable allowlists can be enforced, environment inheritance is off by default, and output is capped.
- Python execution is disabled unless a `PythonPolicy` enables it. Enabled snippets run in a subprocess with a scrubbed environment by default and capped output.
- External CLI harnesses do not inherit the parent environment by default. `--harness-login-env` passes only login/config variables plus explicitly allowed names.

## Redaction

Saved `.tine` files are redacted on write for common secret-bearing key names such as `key`, `secret`, `token`, `password`, `credential`, and `auth`.

This is a best-effort safety layer, not a proof that arbitrary sensitive data cannot appear in free-form model text or tool output. Review artifacts before sharing them outside a trusted boundary.

## Integrity (checksum)

`Run.save()` writes a SHA-256 digest to `metadata.integrity`. `Run.verify_integrity(...)` and `tine verify <run.tine>` recompute the digest and report missing, malformed, or mismatched metadata.

The digest covers the redacted artifact body outside the `metadata` object. It detects accidental corruption and many body edits, but it is **not** tamper-proof: anyone who can edit the file can recompute the digest. For tamper-evidence against an adversary, sign the artifact.

## Signing (`tine-sig/1`)

`tine sign` / `Run.save(sign_key=...)` adds a signature at `metadata.integrity.signature`. It commits to a single canonical *signed view* recomputed from the artifact's content — not to the stored digest — so a body edit plus a digest rewrite still fails verification. The signed boundary (see `TINE_FORMAT.md`) covers the whole body plus an allowlist of authenticity-relevant metadata, and deliberately excludes mutable/derived fields (`tags`, `budget_state`, `autosave`) so ordinary edits don't break a valid signature.

- **HMAC-SHA256** (stdlib, no extra dependency): shared-secret authenticity. Keys shorter than 16 bytes are refused. Keys come from `--key-env` or `--key-file`; they are never written into the artifact.
- **Ed25519** (optional `crypto` extra): public-key signatures. Verifying against the artifact's own embedded key is reported as `verified-tofu` (trust-on-first-use) — the key is self-asserted, not authenticated.
- `tine verify` is **fail-closed**: supplying any key (`--key-env`/`--key-file`/`--pubkey`) or `--require-signature` makes an unsigned, unsupported, or mismatched artifact exit non-zero.

What a valid signature **does** prove: the signed body + allowlisted metadata have not changed since signing by a holder of the key.

What it does **not** prove:
- HMAC is symmetric — it gives intra-group authenticity, **not** non-repudiation; anyone with the shared key could have produced it.
- The `signer` label and an embedded Ed25519 key are self-asserted; opentine has no key→identity binding, PKI, or revocation.
- A *stripped* signature is byte-indistinguishable from a never-signed artifact, so the file alone cannot prove it *should* be signed — establish that expectation out of band.
- Signing provides no confidentiality (artifacts are not encrypted).

## Known Non-Goals

- Opentine does not sandbox arbitrary third-party CLI agents by itself.
- Opentine does not guarantee that model output is safe to execute.
- Opentine does not provide key distribution, identity binding, revocation, or multi-signature (`tine-sig/1` is single-signature).
- Opentine does not currently provide encrypted `.tine` artifacts.
