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

This is the key difference from portable v2 identity. A v3 repository id is a
**content** hash, so two identical forks collapse to one run object. A v2 `.tine`
fork id names the fork **act** — derived from lineage, the retained slice, the
branch, the caller's declared intent, and a recorded nonce, stored in
`metadata.fork`, and provable with `verify_fork_id` — so forking the same point
twice produces two distinct runs rather than one shared id. Both are digests;
neither lets an untrusted run id steer an output path. Importing a v2 run
re-represents its steps as content-addressed event objects, but `load_run`
reconstructs it with its original run id and `metadata.fork`, so a fork's
`verify_fork_id` verdict survives the round-trip. A fork created inside a
repository is a new content-addressed run object that carries no `metadata.fork`
record, so `verify_fork_id` returns `None` (no verdict) for it.

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

Six ref namespaces are accepted — `heads/`, `experiments/`, `promotions/`,
`annotations/`, `tags/`, and `remotes/` — and any other name is refused.
`heads/*`, `experiments/*`, and `promotions/*` move between `run` objects, and
`annotations/*` between `annotation` objects; `tags/*` and `remotes/*` carry no
type constraint and may label any immutable object. `tine init` creates
`refs/annotations`, `refs/heads`, and `refs/tags`.

An `annotations/*` ref carries one further rule. Its target must be an
annotation whose `target_id` is a `run`, and the ref name after `annotations/`
must equal that run's hex digest, so `annotations/<digest>` is the only
`annotations/*` name that can point at an annotation of `run:sha256:<digest>`.
A ref naming a
different run, an annotation without a string `target_id`, or an annotation of
a non-run object is refused rather than stored.

Attestations created by the v3 workflow target runs. These type rules are
enforced on write, read, pack verification, remote ref updates, and by `fsck`.

`fsck` recomputes every ID, validates envelope canonicality, typed links,
shallow boundaries, refs, and the event DAG. Ref updates are compare-and-swap;
a stale expected value is rejected instead of silently overwriting another
writer.

Semantic diff reports common/divergent events, cost, latency, tool path,
content/blob and artifact changes, usage, billing, and evaluation scores.
Exact common/only sets use object identity; the `changed` pairs are a
sequence-position comparison of divergent events, not a causal merge alignment.
Transcript line merging is not an operation. Agents select, compose, fork,
resume, evaluate, attest, and promote run graphs instead.

## Read verbs and their `--json` contract

Five read verbs expose repository engines on the command line. Each renders for
a human by default and emits exactly one JSON object with `--json`:

```bash
tine repo-show heads/main --repo . [--json]      # a whole run, as a step tree
tine context <event-oid> --repo . [--depth N]    # only that event's ancestors
tine repo-log [ref] --repo . [--limit N]         # the event ancestry, one per line
tine repo-diff <left> <right> --repo .           # the semantic diff of two runs
tine repo-search [query] --repo . [--limit N]    # completed runs, by content
```

`repo-show` accepts a ref name or a `run:sha256:…` oid; `context` requires an
`event:sha256:…` oid and defaults to `--depth 8`, the same default the MCP
`context_slice` tool uses, so an operator reproducing what an agent saw gets the
same slice. Every one of the five is read-only and never writes a ref.

`repo-diff` takes a ref name or a run oid on either side, resolves each once, and
compares the resolved objects, so the `left_id`/`right_id` it reports are exactly
what was diffed. It is the `semantic_diff` MCP tool, so the human table and the
JSON carry the same divergence sets and the same five summary dimensions.
With `--exit-code` it follows `git diff`: **0** when the runs are identical,
**1** when they differ. Identical means no event-level divergence — no
`only_left`, no `only_right`, no `changed` — which the JSON also reports as
`identical`. Without `--exit-code` a successful comparison always exits 0.
A usage error is argparse's **2**, which the verb itself never emits, so a script
can distinguish "the runs differ" from "you typed the command wrong".

`repo-search` mirrors the MCP `search_runs` tool exactly: it defaults to
`successful_only` (completed runs only, flipped by `--include-unsuccessful`) and
to `--limit 20`, with `--min-score` and `--model` as the same optional filters.
An empty query lists candidate runs; a query is matched case-insensitively
against event input and output blob text, and the matching prefix comes back as
`matched_text`.

Search is a **bounded scan, not an index**. It walks up to
`MAX_SEARCH_OBJECTS` = 100,000 repository objects per invocation and reads blob
text under further aggregate byte budgets, so its latency grows with repository
size and it is deliberately not on any write path. `--limit` bounds the *result
set*, not the scan — it is what keeps output readable, not what makes the command
fast. Exceeding any of the scan budgets is a refusal, printed as a single
`tine repo-search: <message>` line with exit 1, never a partial result presented
as a complete one.

The JSON objects come from the same writer as `tine show --json`: keys are
sorted, every value passes `json_safe`, and each object carries `command`, which
names the schema below. Within a major version fields are added, never renamed
or removed. A failure that stops a verb producing a result — an unresolvable
ref, a non-event id, a negative depth, a run beyond a shallow boundary — is a
single `tine <verb>: <message>` line on stderr and exit 1, not JSON.

| Verb | Key | Type | Meaning |
| --- | --- | --- | --- |
| `repo-show` | `command` | str | `"repo-show"` |
| | `repo` | str | repository the run was read from |
| | `ref` | str | the ref or run oid as the caller spelled it |
| | `run_object_id` | str | the `run:sha256:…` oid `ref` resolved to |
| | `run` | object | `id`, `status`, `model`, `created_at`, `total_cost`, `step_count`, `tags`, `user_prompt`, `system_prompt` |
| | `steps` | array | the `tine show --json` step shape — `id`, `kind`, `parent_ids`, `model`, `cost`, `duration`, `timestamp`, `inputs`, `outputs`, `usage`, `billing`, `error`, `tool` — where `id` is the event's v3 oid |
| `context` | `command` | str | `"context"` |
| | `repo` | str | repository the slice was read from |
| | `event` | str | the event oid the slice was requested for |
| | `depth` | int | causal depth requested |
| | `count` | int | number of entries |
| | `entries` | array | oldest first: `oid`, `object_type`, `kind` |
| `repo-log` | `command` | str | `"repo-log"` |
| | `repo` | str | repository the ancestry was read from |
| | `ref` | str | the ref or oid the walk started at |
| | `count` | int | number of entries |
| | `entries` | array | `oid`, `object_type`, `kind` |
| `repo-diff` | `command` | str | `"repo-diff"` |
| | `repo` | str | repository the runs were read from |
| | `left`, `right` | str | each side as the caller spelled it |
| | `left_id`, `right_id` | str | the `run:sha256:…` oid each side resolved to |
| | `identical` | bool | the `--exit-code` predicate: no divergent events |
| | `common_events` | array | event oids both runs contain |
| | `only_left`, `only_right` | array | event oids unique to one side |
| | `changed` | array | position-aligned divergent pairs: `index`, `before`, `after`, `fields` |
| | `summary` | object | `cost`, `latency`, `artifacts`, `evaluations`, `tool_path`, each `{left, right}` |
| `repo-search` | `command` | str | `"repo-search"` — distinct from the legacy index-backed `"search"`, which emits `runs` |
| | `repo` | str | repository searched |
| | `query` | str | the query, empty when none was given |
| | `successful_only` | bool | false only with `--include-unsuccessful` |
| | `limit` | int | result cap as requested (default 20) |
| | `min_score`, `model` | float/str or null | the optional filters, null when unset |
| | `count` | int | rows in `results`, never more than `limit` |
| | `results` | array | `run_id`, `status`, `score` (null when unevaluated), `cost`, `latency`, `models`, `matched_text` |

`repo-diff` emits every `SemanticDiff` field verbatim and adds only the envelope
keys above, so a new engine field appears in the JSON without a schema change.

`short_id` is deliberately absent from every v3 object. It is a twelve-character
prefix, and a v3 oid's first twelve characters are the constant `run:sha256:` or
`event:sha25`, so the field would be identical for every object in the
repository. Human output shortens an oid as `type:<12 hex digits>` instead,
dropping the hash-name segment rather than the digest.

`entries` carries no payload in either verb, exactly like the human line. Event
payloads are unbounded recorded content; `tine object <oid> --repo .` is the
verb that resolves one, with `--resolve-blobs` to follow its content blobs.

Everything these verbs print is recorded content — prompts, tool names, model
strings, and ids an agent may have been fed by an attacker. Human rendering
routes all of it through the CLI's terminal sanitizer, which strips control
bytes and bidi overrides and escapes markup. `--json` does not sanitize: it is
not a terminal, and a consumer must see the bytes as recorded.

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
capture failures explicitly when Git state is unavailable or a patch exceeds the
16 MiB capture ceiling. Untracked paths mark the worktree dirty and are listed,
but their contents are not captured, so the manifest is explicitly incomplete
until they are added or staged. Importers accept native
OpenTine records, JSONL, and OpenTelemetry GenAI spans or complete OTLP/JSON
exports. Malformed JSONL lines are skipped independently, large integers are
string-preserved, and imported dependencies are ordered before recording.
Span lookup is qualified by trace identity; duplicates and dependency cycles
are rejected, while unresolved boundaries in partial traces are retained on the
stored event as `unresolved_span_refs`.
Framework importers best-effort normalize common serialized shapes
from LangChain, LlamaIndex, AutoGen, CrewAI, and OpenAI Agents.

Import parsers can normalize larger input sources, but one stored `Recorder` run
is limited to 3,000 events. The limit is checked before any event data is written;
bulk imports preserve dependency order and commit one final run snapshot. This
keeps even a worst-case graph with unique input and output blobs below the 10,000
object pack-negotiation ceiling.

Local search retrieves successful runs and evaluation scores. `context_slice`
walks only parent and causal links needed for an event. Forking can replace
model, prompt, or policy from the last good event. Evaluations and approvals
are content-addressed, tamper-evident attestations (the `signer` is self-asserted
unless a signature is attached); promotion is a CAS ref update.

When an MCP server starts inside a repository, it adds `search_runs`,
`inspect_object`, `context_slice`, `semantic_diff`, `fork_run_v3`,
`resume_run_v3`, `evaluate_run`, and `attest_run`, plus verified object
resources. `promote_run` is not among them by default. It is registered only
when the host opts in with `allow_promotion=True`, because a promotion ref is a
release gate and the run content an MCP client reads is untrusted, so text
recorded inside a run can ask the model to promote a run of an attacker's
choosing. `fork_run_v3` and `resume_run_v3` may write only `experiments/*`
refs; the namespace is checked on the canonical ref name, so mainline,
promotion, tag, and remote-tracking refs stay operator-only.

Search and inspection fail closed at explicit implementation ceilings: search
indexes at most 100,000 objects, 10,000 candidate runs, and 100,000 aggregate
event references while bounding structured and blob source bytes. Direct blob
inspection returns a verified 512 KiB prefix; resolved inspection returns at
most 1 MiB across 64 referenced blobs and marks truncated results explicitly.

## Packs and synchronization

`TINEPACK3` packs are canonical manifests of verified envelopes, compressed
with a SHA-256 checksum. Negotiation sends only objects reachable from wanted
IDs that the receiver does not already have. Packs support shallow boundaries
and filtered fetch without pretending omitted history is present. Compressed
transfers and decompressed manifests are capped at 256 MiB and trailing zlib
streams/data are rejected. Repository-wide shallow state is validated and
capped at 10,000 object IDs / 1 MiB, then cached for link verification; local
object and negotiation listings stop at protocol limits before sorting. Client
control responses are streamed under a 1 MiB
raw-byte cap and non-identity HTTP content encodings are rejected; resumable
offsets must advance, loops are bounded, transient short reads retain partial
upload state, and abandoned upload state is reaped.

The pack layer is explicit about omitted history; the local read surface treats
it in two different ways, and a reader of a shallow clone must know which. `log`,
`diff`, and `context_slice` stop at the boundary silently: a cut object is
skipped, and `SemanticDiff` carries no truncation marker, so its cost, latency,
tool-path, and artifact aggregates are computed only over the events present
locally and omit history beyond the boundary without saying so. `load_run`,
`fork`, and `resume` instead refuse, with a typed error naming the object that
lies beyond the repository's shallow fetch boundary and directing the caller to
deepen the fetch. Treat aggregates read from a shallow clone as lower bounds
until the clone is deepened.

The HTTP protocol exposes:

- unauthenticated capability discovery;
- authenticated ref discovery and missing-object negotiation;
- deterministic pack download and resumable, checksummed upload;
- depth/object-type filtered fetch;
- compare-and-swap ref updates.

Clients require HTTPS except when the base URL host is a literal loopback IP
address (`127.0.0.1`, `::1`), which is accepted over plain `http://` with no
opt-in, or when `--allow-insecure` development is requested explicitly. The
hostname `localhost` is not a literal address and is refused without that flag.
Authenticated clients ignore ambient proxy variables so local development
credentials are not forwarded unexpectedly. Push uploads verified missing
objects before attempting the CAS ref update.

## Reference self-hosted remote

Extension interfaces cover `ObjectStore`, `IndexBackend`, `IdentityProvider`,
`AuthorizationPolicy`, `KeyProvider`, `AuditSink`, `RetentionHook`, and
`AdmissionPolicy`. The reference deployment implements them with encrypted
filesystem objects and SQLite. A `StaticTokenIdentityProvider` supports
development identities. Retention hooks gate object deletion, and admission
policies can reject pack bytes, object counts, or ref updates; resumable uploads
invoke admission at declaration and again after pack inspection, so a policy can
bound both bytes and object counts.

The security properties of that deployment — encryption at rest and key
provision, identity and tenant-scoped authorization, the HMAC-chained audit log
and its authenticated head outside SQLite, the listing and annotation ceilings,
and the operator responsibilities that remain — are specified in
[SECURITY_MODEL.md](SECURITY_MODEL.md) and are not restated here.

The 0.3.0 scope is an enterprise repository foundation. The bundled bounded
WSGI server targets development and small self-hosted deployments, not turnkey
high availability. S3-compatible
object storage, PostgreSQL/search backends, managed identity configuration, and
a hosted control plane remain production adapters or later 0.3.x work—not
claims of this reference server.
