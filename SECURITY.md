# Security Policy

## Supported Versions

OpenTine is a 0.x line. Only the most recent release receives security fixes,
and fixes ship as a new release rather than as a patch to an older tag. There
are no backports to earlier 0.x versions.

| Version | Supported |
| --- | --- |
| 0.3.x | Yes |
| 0.2.x | No |
| 0.1.x | No |

If you are running an earlier version, upgrade before reporting. The issue may
already be fixed in the current release.

## Reporting a Vulnerability

Please report suspected security issues privately, before public disclosure,
through one of these channels:

1. GitHub's
   [private vulnerability report](https://github.com/0xcircuitbreaker/opentine/security/advisories/new).
   If that page returns an error or shows no reporting form, private reporting
   is not enabled on the repository; use the fallback below.
2. Email `0xcircuitbreaker@protonmail.com`.

Include a minimal reproduction, the affected OpenTine version or commit,
operating system, Python version, and whether an external harness or model
provider was involved.

Do not include secrets or private `.tine` artifacts in public issues.

Reports are handled on a best-effort basis by an unfunded project. Expect an
acknowledgement within 7 days. No fix timeline is promised. If you have not
received an acknowledgement within 14 days, assume the report did not reach a
maintainer and use your own judgement about disclosure.

## Scope

Before filing, check the documented non-goals in
[SECURITY_MODEL.md](docs/SECURITY_MODEL.md#known-non-goals). Behavior listed there —
for example, that OpenTine does not sandbox arbitrary third-party CLI agents by
itself, and does not guarantee that model output is safe to execute — is a
known limitation, not a vulnerability.

## Security Model

OpenTine's detailed security posture, default tool policies, redaction behavior, and current non-goals are documented in [SECURITY_MODEL.md](docs/SECURITY_MODEL.md).
