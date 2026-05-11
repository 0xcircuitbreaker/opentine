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

## Integrity

`Run.save()` writes a SHA-256 digest to `metadata.integrity`. `Run.verify_integrity(...)` and `tine verify <run.tine>` recompute the digest and report missing, malformed, or mismatched metadata.

The current digest covers the redacted artifact body outside the `metadata` object. It detects accidental corruption and many body edits, but it is not tamper-proof. Anyone who can edit the file can rewrite the digest. HMAC, public-key signing, and stronger provenance attestations are future work.

## Known Non-Goals

- Opentine does not sandbox arbitrary third-party CLI agents by itself.
- Opentine does not guarantee that model output is safe to execute.
- Opentine does not sign release artifacts in this pass.
- Opentine does not currently provide encrypted `.tine` artifacts.
