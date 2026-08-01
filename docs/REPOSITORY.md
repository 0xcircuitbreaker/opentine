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

## Verb names: the `repo-` prefix rule

`tine` carries two command families. The legacy v2 verbs read and write portable
`.tine` artifacts through the `.tine_runs` file index; the v3 verbs read and
write objects and refs inside a `.tine` repository. They are different stores,
so where both families need the same word, the v3 verb takes a `repo-` prefix.

**The prefix is a collision marker, not a namespace.** It appears only where a
legacy verb already owns the plain name, which is why `context`, `attest`,
`evaluate`, and `promote` are bare — v2 has no such verbs. Do not add a
`repo-` prefix for symmetry.

| Legacy verb (`.tine` file + `.tine_runs` index) | v3 verb (`.tine` repository) | MCP tool |
| --- | --- | --- |
| `tine show <run>` | `tine repo-show <ref-or-oid>` | — (`inspect_object` is `tine object`) |
| `tine search <query>` | `tine repo-search [query]` | `search_runs` |
| `tine diff <a> <b>` | `tine repo-diff <a> <b>` | `semantic_diff` |
| `tine fork <run> --from-step N` | `tine repo-fork <ref-or-oid> --from-event OID` | `fork_run_v3` |
| `tine resume <run>` | `tine repo-resume <ref-or-oid>` | `resume_run_v3` |

`repo-log` is the one prefix without a collision: `log` was never a legacy verb,
but `repo-log` shipped in 0.3.0 and renaming a released verb is a breaking
change, so it is grandfathered. tests/test_repo_cli_parity.py asserts the rule
and pins that single exception, so a second one cannot appear by accident.

The two families never share state. `tine fork` branches a run *file* and writes
`.tine_runs/<run-id>.tine`; `tine repo-fork` branches a run *object* and moves a
repository ref. A v2 artifact reaches the v3 side only through `tine migrate-v3`.

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

## Write verbs

Three verbs mutate a repository. They are the operator half of the surface: MCP
withholds `promote_run` unless the host opts in, because a model reading
untrusted run content must not be able to move a release gate, but the person at
the terminal already holds the repository.

```bash
tine attest <run-ref-or-oid> --signer NAME (--claim JSON | --claim-file PATH) \
    [--evidence OID]... [--repo .] [--json]
tine evaluate <run-ref-or-oid> --evaluator NAME --score NAME=VALUE... [--json]
tine promote <run-ref-or-oid> --name NAME [--expected-old OID] [--json]
```

Each accepts a ref name or a `run:sha256:…` oid and **resolves it first**. That
resolution is not cosmetic: `attest` hands `target_id` to the object store,
whose link check requires an object that already exists, and `promote` hands its
run into `update_ref`, which rejects a ref string outright. After resolving,
each verb makes exactly one engine call — `Repo.attest` or `Repo.promote` — so a
CLI-written object is byte-identical to the object the matching MCP tool writes.
A target that resolves to no object, or to something that is not a run, is
refused before anything is written.

`attest` stores the claim verbatim inside a content-addressed attestation. The
claim must parse to a JSON **object**; a list, number, or string is refused,
because every reader — the association scan behind `repo-diff`'s
`summary.evaluations`, and `repo-search`'s score scan — reads a claim as a
mapping. `--evidence` may be repeated and each value must be an existing object.

`evaluate` is `attest` with the claim fixed to
`{"kind": "evaluation", "scores": {…}}` and `signer` taken from `--evaluator` —
exactly what the MCP `evaluate_run` tool builds. There is deliberately only one
evaluation claim shape in the format; a second would be scores no reader could
see. Each `--score` must be a finite number, and a repeated name is refused
rather than silently resolved.

There is no `--sign`/`--signature` flag. v3 ships no attestation signing helper,
so a `signer` is a self-asserted label, and the human output says `unsigned`
rather than implying a binding that does not exist.

`promote` compare-and-swaps `promotions/<name>`. **`--expected-old` omitted means
expect no existing ref**, so creating a promotion is the default and *moving* one
always requires naming the value being replaced; the refusal on a conflict prints
the current oid and the `--expected-old` invocation that would move it. There is
no `--force`, and there will not be one: a release gate that can be overwritten
without stating what it overwrote is not a gate.

Their `--json` object is a **receipt**, emitted only after the write has
succeeded. A failure that stops the result — a CAS conflict, an unresolvable or
non-run target, an invalid claim or score — is a single `tine <verb>: <message>`
line on stderr with exit 1 and *no JSON on stdout*, so a consumer never has to
parse an object to learn whether the repository changed. A usage error is
argparse's 2, which these verbs never emit themselves.

| Verb | Key | Type | Meaning |
| --- | --- | --- | --- |
| `attest` | `command` | str | `"attest"` |
| | `repo` | str | repository written to |
| | `target` | str | the ref or oid as the caller spelled it |
| | `run_id` | str | the `run:sha256:…` oid `target` resolved to |
| | `attestation_id` | str | the new `attestation:sha256:…` oid |
| | `signer` | str | the self-asserted signer label |
| | `claim` | object | the claim as stored |
| | `evidence_ids` | array | supporting object ids, empty by default |
| | `signed` | bool | always `false` — no signing helper exists yet |
| `evaluate` | `command` | str | `"evaluate"` |
| | `repo`, `target`, `run_id`, `attestation_id` | str | as above |
| | `evaluator` | str | stored as the attestation's `signer` |
| | `scores` | object | the finite scores as stored |
| | `signed` | bool | always `false` |
| `promote` | `command` | str | `"promote"` |
| | `repo`, `target`, `run_id` | str | as above |
| | `name` | str | the promotion name |
| | `ref` | str | always `"promotions/<name>"` |
| | `expected_old` | str or null | the compare-and-swap value as given |
| | `created` | bool | true exactly when `expected_old` was null |

Appending to a repository written by an older release is a release gate, tested
the same way reading one is: every verb runs against a copy of every committed
golden repository from 0.3.0 onward, and the copy must `fsck` clean afterwards.

## Lineage verbs

Two more verbs branch a run graph. They are the CLI twins of the MCP
`fork_run_v3` and `resume_run_v3` tools, and both make exactly one engine call,
`Repo.fork`, with the same arguments the tool passes — so a CLI-written fork is
the same content-addressed object the tool writes.

```bash
tine repo-fork <run-ref-or-oid> --from-event OID --ref REF \
    [--model M] [--prompt P] [--policy JSON] [--repo .] [--json]
tine repo-resume <run-ref-or-oid> --ref REF [--repo .] [--json]
```

`repo-fork` rebuilds a run from the causal closure of `--from-event`, so the
forked run contains that event and its ancestors and nothing later. `--model`,
`--prompt`, and `--policy` are the three overrides `fork_run_v3` accepts;
`--policy` must parse to a JSON object, and an omitted flag is identical to an
absent override key, not to a null one.

`repo-resume` is the same fork taken at the run's **last verified tip** with
`overrides={"resume": True}`, which is what makes the new run `status:
"running"` instead of a plain branch. A run with no event tip cannot be resumed
and is refused by name rather than crashing on an empty tip list.

Both accept a ref name or a `run:sha256:…` oid and resolve it first, then apply
the run-type check `resume_run_v3` performs; a target that is not a run is
refused before anything is written.

### `--ref` is required, has no default, and is not confined

`--ref` must be given on both verbs and there is deliberately **no default**.
A fork's ref update is an unconditional overwrite — it compare-and-swaps against
the value it just read — so a defaulted destination would mean a bare
`tine repo-fork RUN` silently advancing whatever ref the default named. Every
fork destination is an explicit operator choice.

The CLI is also deliberately **not** confined to `experiments/*`. That
confinement is real, and it stays where it is: at the MCP boundary, in
`mcp_repository._writable_ref`. Its threat model is model-controlled input — the
ref an MCP client picks is chosen from run content it just read, so an
unconfined fork tool would make "fork onto `heads/main`" a one-step
prompt-injection payload. An operator at a terminal already holds the
repository and can move any ref with `tine promote` or a direct write, so
confining the CLI would buy no security and would only push people around it.
The CLI still validates the ref name (canonicalizing it *before* the write, so a
malformed ref is refused rather than reported after the object exists).

Their `--json` object is a **receipt**, emitted only after the write succeeded;
a refusal is one `tine repo-fork: <message>` / `tine repo-resume: <message>`
line on stderr with exit 1 and no JSON on stdout.

| Verb | Key | Type | Meaning |
| --- | --- | --- | --- |
| `repo-fork` | `command` | str | `"repo-fork"` |
| | `repo` | str | repository written to |
| | `target` | str | the ref or oid as the caller spelled it |
| | `source_run_id` | str | the `run:sha256:…` oid `target` resolved to |
| | `from_event` | str | the `event:sha256:…` fork point |
| | `ref` | str | the canonicalized ref now pointing at the new run |
| | `run_id` | str | the new `run:sha256:…` oid |
| | `overrides` | object | only the overrides actually given: `model`, `prompt`, `policy` |
| | `resumed` | bool | always `false` |
| `repo-resume` | `command` | str | `"repo-resume"` |
| | `repo`, `target`, `source_run_id`, `ref`, `run_id` | str | as above |
| | `from_event` | str | the tip the resume forked from |
| | `overrides` | object | always `{"resume": true}` |
| | `resumed` | bool | always `true` |

Forking a repository an older release wrote is a release gate exactly as
appending to one is: both verbs run against a copy of every committed golden
repository from 0.3.0 onward, and the copy must `fsck` clean afterwards.

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

Promotion being an operator CLI verb (`tine promote`) does not change that
default. The two surfaces are trusted differently on purpose: an operator at a
terminal already holds the repository, while a model over MCP is acting on
content it read out of that repository. `allow_promotion` remains `False`.

### CLI ↔ MCP parity, and the four places they differ

Every MCP tool has a CLI verb and every v3 verb is accounted for.
tests/test_repo_cli_parity.py holds the map and fails CI in **both**
directions: a new tool without a verb is red, and so is a verb that is neither
mapped to a tool nor listed as deliberately CLI-only.

| MCP tool | CLI verb |
| --- | --- |
| `search_runs` | `tine repo-search` |
| `inspect_object` | `tine object` |
| `context_slice` | `tine context` |
| `semantic_diff` | `tine repo-diff` |
| `fork_run_v3` | `tine repo-fork` |
| `resume_run_v3` | `tine repo-resume` |
| `evaluate_run` | `tine evaluate` |
| `attest_run` | `tine attest` |
| `promote_run` | `tine promote` |

The CLI-only verbs are `init`, `fsck`, `pack`, `migrate-v3`, `fetch`, `push`,
and `clone` — repository administration and transport, each handing out a
filesystem path, a network endpoint, or a credential that has no business being
driven by run content — plus `repo-show` and `repo-log`, which render a run tree
and an event ancestry for a *terminal*; a model reads the same objects through
`inspect_object` and `context_slice`.

Four differences are deliberate. Each is asserted as a fact in the parity test,
so making the surfaces agree turns CI red and forces the argument to be re-made.

1. **`promote` is unconditional on the CLI, opt-in over MCP.** No flag, no
   environment variable. The reasoning is the paragraph above.
2. **`repo-fork` / `repo-resume` are not confined to `experiments/*`.** The
   namespace confinement is an MCP-boundary control against model-chosen refs;
   see the lineage-verb section.
3. **CLI `--json` receipts are a superset of the MCP return.** `fork_run_v3`
   returns `{ref, run_id}` — a model's working set. The CLI receipt adds what
   the operator typed and what it resolved to, because it is an audit artifact.
   Shared keys always carry the same values.
4. **The CLI refuses non-finite evaluation scores; MCP passes them through.**
   `tine evaluate --score q=nan` is refused at the argument door, naming the
   flag, before any engine call, because `repo-search` averages scores.
   `evaluate_run` takes an already-typed `dict[str, float]` and adds no check of
   its own, so the value travels into `canonical_json` and is refused there as a
   kernel error about JSON encoding. Nothing non-finite is stored either way —
   the kernel is the backstop — but the CLI is the stricter and more legible
   surface, and that asymmetry is recorded rather than levelled.

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
