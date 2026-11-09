# Third-party security audit: kickoff and scope (0.50)

**Status.** Scoped, **not engaged.** The 1.0 criteria require an independent
audit (ROADMAP §10, "1.0 criteria", item 1). The 0.50 acceptance requires
only that the audit has **started**. This document is the scope we hand to an
auditor. Choosing and contracting an auditor, agreeing dates and receiving the
report are tasks for the maintainers. No code change can do them, and no
release note may say that they have been done. Until a report is published in
this folder, criterion 1 is **not met**.

## Open items for the maintainers

- [ ] Choose an independent firm with no prior work on opentine, and record
      the name and the engagement dates here.
- [ ] Agree on this scope (or an amended version) in the statement of work.
- [ ] Give the auditor the pinned commit, `uv.lock`, the built
      `tine-verify.pyz` and its digest, and a test `tine serve` deployment
      (with `--oidc-issuer` and with static tokens).
- [ ] Set up a private channel for findings (SECURITY.md, "Reporting a
      Vulnerability") and agree on a coordinated disclosure date.
- [ ] Publish the report, or its executive summary, in this folder, with each
      finding's fix, its release and the test that pins it.

## In scope

1. **The `tine` CLI** (`opentine/`, Python 3.11+), with emphasis on
   everything that parses untrusted input. That covers `.tine` artifacts v2 to
   v5, bundles, packs (`TINEPACK3`/`TINEPACK5`), importers (`tine import`,
   all formats), OTLP/HTTP and OTLP/gRPC ingest, the MCP server and MCP
   proxy, hook payloads, plugins (`opentine-plugin-allow-1`), redaction and
   the pre-push gate, purge and tombstones, signing and key storage (encrypted key files,
   PKCS#11, KMS, SSH, PQ), and `tine tenant export|import`.
2. **The verifiers**: the Python verifier (`tine verify --offline`), the
   standalone `tine-verify.pyz` (`opentine/_pyz/`, built by
   `opentine/_pyz_build.py`), the TypeScript verifier (`ts/verifier/`) and the
   verified reads of `@opentine/sdk` (`ts/sdk/`). The question is whether all
   three agree on every pinned vector (`docs/conformance/vectors/`, frozen at
   0.48, see `tests/freeze_inventory.py`) and whether any input makes one of
   them accept what the SPEC rejects.
3. **`tine serve`** (`opentine/remote/`): authentication (static tokens,
   OIDC/JWKS), per-tenant authorization, the uniform-404 rule, quotas and
   auth throttling, pack ingest and resumable uploads, ref transactions and
   admission policies, the transparency log and receipts, webhooks
   (`tine-webhook/1`, SSRF guards), share links, Reviews, projects, the
   coordination backend, WORM storage and sealed (encrypted-at-rest) objects.
4. **The hosted APIs**: every route in `docs/api/openapi-v1.yaml` (generated
   from `opentine/remote/_api_routes.py`), tested black-box with
   `tests/api_conformance/` against a deployment. The hosted web front end
   (opentine-web, ROADMAP §11) is in scope only where it calls these APIs.
5. **The release chain**: `.github/workflows/publish.yml` and
   `supply-chain.yml`, the reproducible pyz, and the release inventory
   (`scripts/check_release_inventory.py`).

## Out of scope

- Third-party services that opentine talks to: model providers, Sigstore
  (Fulcio and Rekor), RFC 3161 TSAs, forges, Zenodo and Hugging Face. Our
  clients for these services are in scope.
- The security of the agents being recorded, and of the code those agents
  run. Subprocess timeouts are resource limits, not a sandbox (README, Security).
- Denial of service by a tenant that the operator has configured with no
  quota.
- Operator mistakes that the documentation warns about (for example,
  `--insecure-dev` or `--allow-weak-tokens` in production).
- Known non-goals listed in `docs/SECURITY_MODEL.md` ("Known Non-Goals").

## Threat model pointers

- `docs/SECURITY_MODEL.md`: trust boundaries. See in particular "V3
  repository and remote", "Artifacts you did not write are untrusted input",
  "The standalone verifier", "MCP server" and "Key storage and signers".
- `docs/security/otlp-grpc-review.md`: the internal review of the 0.48 OTLP
  receiver.
- `docs/SPEC.md` §2.8 (packs; a client recomputes every oid it fetches), §4 (signing), §8.10 to
  §8.23 (transparency, remote API, hooks, admission, Reviews, coordination,
  witnesses).
- `docs/PII.md` and `docs/SECURITY_MODEL.md` "Redaction" cover what
  redaction does and does not promise.
- `docs/LEAVING.md`: what leaves a server, and what deliberately does not.

## Deliverables we ask for

1. A report with each finding's severity (CVSS v4 or the firm's own scale),
   affected component and version, a reproduction and a suggested fix.
2. A retest of each fix, with the outcome recorded against the release that
   shipped the fix.
3. A statement of coverage: what was reviewed and to what depth, what was
   only sampled, and what was not reached.
4. Permission to publish the report, or an executive summary, in this folder.

## What the codebase already gives the auditor

- An offline test suite (`uv run python -m pytest`), conformance vectors
  answered by Python, TS and the pyz, and fuzz harnesses
  (`scripts/fuzz_otlp.py`).
- The nightly stress job (`.github/workflows/nightly-stress.yml`).
- The air-gapped audit kit (`tine audit-kit`, 0.49).
- The leave-the-service test (`tests/test_050_leave_service.py`).
