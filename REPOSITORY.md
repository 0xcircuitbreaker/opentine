# V3 repository and remote protocol

OpenTine 0.3.0 stores agent history under `.tine/` using Git-shaped concepts,
while retaining portable `*.tine` v2 compatibility files.

## Object model

The immutable object types are:

| Type | Purpose |
|---|---|
| `blob` | raw prompts, outputs, patches, tool results, artifacts, and manifests |
| `event` | normalized model, tool, human, policy, approval, error, or subagent activity |
| `run` | event roots/tips plus code, environment, policy, budget, and pricing manifests |
| `attestation` | signatures, evaluations, approvals, and provenance claims |
| `annotation` | separately versioned mutable human/system metadata |

An object ID is `TYPE:sha256:HEX`, computed over the type, schema version, and
canonical stored bytes. JSON uses RFC 8785/JCS encoding; blobs retain raw bytes.
Credential redaction precedes canonicalization and hashing. Identical objects
deduplicate naturally.

Integer inputs outside JSON's interoperable ±(2**53−1) range are rejected;
callers must encode 64-bit identifiers, nanosecond timestamps, or arbitrary-
precision amounts as strings instead of accepting silent IEEE-754 rounding.

The dependency-free trusted kernel owns only canonical encoding, typed IDs,
immutable envelopes, typed parent/causal-link checks, object verification, and
a tiny repository protocol. CI caps the complete kernel and every production
Python module at 250 physical lines.

## Local layout and operations

`.tine/` contains loose objects, refs, reflogs, deterministic compressed packs,
configuration, shallow boundaries, and rebuildable indexes. The public API
includes `Repo.init/open`, `put/get`, CAS `update_ref`, `log`, semantic `diff`,
`fork`, `verify/fsck`, `pack`, `fetch`, and `push`.

```python
from opentine import Repo

repo = Repo.init("workspace")
oid = repo.put("blob", b"artifact")
repo.update_ref("tags/example", oid, expected_old=None)
assert repo.fsck(deep=True).ok
```

`fsck` recomputes every ID, validates envelope canonicality, typed links,
shallow boundaries, refs, and the event DAG. Ref updates are compare-and-swap;
a stale expected value is rejected instead of silently overwriting another
writer.

Semantic diff reports common/divergent events, cost, latency, tool path,
content/blob and artifact changes, usage, billing, and evaluation scores.
Transcript line merging is not an operation. Agents select, compose, fork,
resume, evaluate, attest, and promote run graphs instead.

## V2 migration

```bash
tine init .
tine migrate-v3 legacy.tine --repo . --ref heads/imported
```

Migration:

1. stores the exact original v2 bytes as a legacy blob;
2. records the original checksum and signature-verification result;
3. redacts structured v3 content before canonicalization and hashing;
4. rebuilds object IDs and causal links;
5. stores a deterministic old-step-ID → event-ID map;
6. marks any v2 signature as `legacy_blob_only`.

Migration is fail-closed by default for a bad integrity digest and for any
signature the caller requested to verify. `--allow-unverified` is an explicit
escape hatch and the failed result remains recorded. The exact legacy blob is
intentionally not redacted, so it can contain credentials present in the source
artifact and should be treated as sensitive.

It never claims a v2 signature authenticates newly generated v3 objects. This
also closes a v2 identity limitation: v2 compatibility saves can redact fields
after a step ID was formed, whereas v3 always hashes the redacted stored bytes.

## Agent-facing traces

`Recorder` starts a run with code/dirty patch, environment, policy, budget, and
pricing manifests, then appends normalized events live. The code manifest marks
capture failures explicitly when Git state is unavailable. Importers accept native
OpenTine records, JSONL, and OpenTelemetry GenAI spans or complete OTLP/JSON
exports. Malformed JSONL lines are skipped independently, large integers are
string-preserved, and imported dependencies are ordered before recording.
Framework importers best-effort normalize common serialized shapes
from LangChain, LlamaIndex, AutoGen, CrewAI, and OpenAI Agents.

Local search retrieves successful runs and evaluation scores. `context_slice`
walks only parent and causal links needed for an event. Forking can replace
model, prompt, or policy from the last good event. Evaluations and approvals
are content-addressed, tamper-evident attestations (the `signer` is self-asserted
unless a signature is attached); promotion is a CAS ref update.

When an MCP server starts inside a repository, it adds `search_runs`,
`inspect_object`, `context_slice`, `semantic_diff`, `fork_run_v3`,
`resume_run_v3`, `evaluate_run`, `attest_run`, and `promote_run`, plus verified
object resources.

## Packs and synchronization

`TINEPACK3` packs are canonical manifests of verified envelopes, compressed
with a SHA-256 checksum. Negotiation sends only objects reachable from wanted
IDs that the receiver does not already have. Packs support shallow boundaries
and filtered fetch without pretending omitted history is present. Compressed
transfers and decompressed manifests are capped at 256 MiB and trailing zlib
streams/data are rejected. Client control responses are streamed under a 1 MiB
cap; resumable offsets must advance, loops are bounded, transient short reads
retain partial upload state, and abandoned upload state is reaped.

The HTTP protocol exposes:

- unauthenticated capability discovery;
- authenticated ref discovery and missing-object negotiation;
- deterministic pack download and resumable, checksummed upload;
- depth/object-type filtered fetch;
- compare-and-swap ref updates.

Clients require HTTPS except for loopback or explicit `--allow-insecure`
development. Push uploads verified missing objects before attempting the CAS
ref update.

## Reference self-hosted remote

The reference deployment uses encrypted filesystem objects and SQLite for
object metadata, refs, and HMAC-chained audit records with an authenticated
head outside SQLite. AES-GCM is required by
the reference server; production deployments provide a KMS-backed
`KeyProvider`.

Extension interfaces cover `ObjectStore`, `IndexBackend`, `IdentityProvider`,
`AuthorizationPolicy`, `KeyProvider`, `AuditSink`, `RetentionHook`, and
`AdmissionPolicy`. Static tokens support development; a built-in `JWTVerifier`
(RS256/ES256, JWKS + issuer/audience/expiry) backs OIDC, or a custom verifier can
be injected. Validated claims map to reader/writer/admin roles and a tenant.

Authorization is tenant-scoped and enforced on every read and mutating path.
Audit verification detects interior edits and end truncation without appending
another row. Legacy rows need an explicit trust-on-migration flag and report
`legacy-unverified`; the flag cannot recover a lost anchor. A committed row left
one step ahead of its anchor is healed automatically, while other recovery needs
an exact `--reanchor-audit-head` value (triggers remain defense in depth).
Production KMS adapters must provide external audit-key derivation or an explicit
audit key; the reference app fails closed instead of writing a fallback key next
to SQLite. Retention hooks gate object deletion, and
admission policies can reject pack bytes/object counts or ref updates based on
rate and budget policy. Resumable uploads invoke admission at declaration and
again after pack inspection so policies can bound both bytes and object counts.

The 0.3.0 scope is an enterprise repository foundation. The bundled bounded
WSGI server targets development and small self-hosted deployments, not turnkey
high availability. S3-compatible
object storage, PostgreSQL/search backends, managed identity configuration, and
a hosted control plane remain production adapters or later 0.3.x work—not
claims of this reference server.
