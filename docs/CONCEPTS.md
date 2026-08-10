# Concepts

The mental model in one place. This page defines the words the CLI, the Python
API, and the other documents use; each section links to the reference that owns
the details rather than restating them.

1. [A run is a graph, not a transcript](#a-run-is-a-graph-not-a-transcript)
2. [Content addressing: the digest is the name](#content-addressing-the-digest-is-the-name)
3. [Two surfaces: the `.tine` file and the `.tine/` repository](#two-surfaces-the-tine-file-and-the-tine-repository)
4. [Steps and events](#steps-and-events)
5. [Refs and reflogs](#refs-and-reflogs)
6. [Verify](#verify)
7. [Fork](#fork)
8. [Replay](#replay)
9. [Diff](#diff)
10. [Attest, evaluate, promote](#attest-evaluate-promote)
11. [Cost](#cost)
12. [Vocabulary](#vocabulary)

## A run is a graph, not a transcript

A run is a directed acyclic graph of what the agent actually did — model calls,
tool calls, human turns, policy decisions, subagent work, errors — with edges
recording *what caused what*. It is not a flat chat log, and OpenTine never
line-merges one run into another. Two runs are compared by asking which nodes
they share and which they do not.

Every node carries its inputs, its outputs, its model, its token usage, its
duration, and its cost. That is enough to re-derive the run, to price it, and to
say precisely where two attempts diverged.

## Content addressing: the digest is the name

Nothing in OpenTine is named by a counter or a UUID you have to trust. A node's
identity **is** the SHA-256 digest of its content, so an id cannot be
reassigned, and two producers that recorded the same thing produce the same id
without coordinating.

Two consequences follow, and they explain most of the design:

- **Identical things deduplicate.** Storing the same prompt twice stores one
  object.
- **Tampering is detectable by recomputation.** `tine verify` (v2) and
  `tine fsck` (v3) recompute ids rather than reading a stored claim.

Redaction runs *before* canonicalization and hashing, so a redacted value is
what the digest commits to — you cannot recover a secret by rehashing.

JSON is canonicalized with RFC 8785/JCS before hashing, which is why integers
outside JSON's interoperable ±(2**53−1) range are refused instead of being
silently rounded: two readers that disagree about a number would disagree about
every digest computed over it. Encode large ids and nanosecond timestamps as
strings. See [TINE_FORMAT.md](TINE_FORMAT.md).

## Two surfaces: the `.tine` file and the `.tine/` repository

These are deliberately separate, and they never share state.

|  | Portable artifact | Repository |
|---|---|---|
| On disk | one `*.tine` file (format v2) | a `.tine/` directory (v3 objects) |
| Holds | one run graph | many runs, refs, reflogs, packs, indexes |
| Index | `.tine_runs/index.json` | repository indexes, rebuilt by `fsck` |
| Verbs | `show`, `verify`, `sign`, `fork`, `replay`, `diff`, `resume`, `ls`, `search`, `stats`, `tag` | `init`, `repo-show`, `repo-log`, `repo-diff`, `repo-search`, `context`, `repo-fork`, `repo-resume`, `attest`, `evaluate`, `promote`, `object`, `pack`, `fsck`, `fetch`, `push`, `clone` |
| Authenticity | Ed25519 / HMAC signature over the artifact | attestations over content-addressed objects |
| Good for | mailing a run, attaching to a bug, archiving | history, branching, release gates, sync |

A v2 artifact reaches the v3 side only through `tine migrate-v3`, which keeps
the original artifact byte-exact as a legacy blob, records its original
integrity/signature verdict, and stores an old→new id map. A legacy signature
stays scoped to the legacy blob; it is never presented as a signature over the
new v3 objects.

Where both families need the same word, the v3 verb takes a `repo-` prefix —
`show`/`repo-show`, `fork`/`repo-fork`. The prefix is a collision marker, not a
namespace, which is why `context`, `attest`, `evaluate`, and `promote` are bare.
See [REPOSITORY.md](REPOSITORY.md#verb-names-the-repo--prefix-rule).

## Steps and events

The two surfaces spell a node differently, and the difference is real.

**v2 steps** have five kinds — `think`, `tool`, `model`, `done`, `error` — and a
step id is a SHA-256 over kind, parent links, inputs, outputs, model/tool
metadata, and error. Timestamps, duration, cost, and token usage are *recorded
but not hashed*, so two steps with identical content but different cost share an
id and surface in `diff` as a `changed` pair rather than as an add plus a
delete.

**v3 events** have seven kinds — `model`, `tool`, `human`, `policy`, `approval`,
`subagent`, `error` — because a repository has to represent approvals and human
turns that a single-agent transcript never had. Record a failed step as an
`error` event rather than dropping it: a partial run that is inspectable is
worth more than a clean one that lies.

A v3 `run` object holds its events' roots and tips plus five manifests — code,
environment, policy, budget, and pricing — so the conditions a run executed
under travel with the run.

## Refs and reflogs

A **ref** is a mutable name pointing at an immutable object, exactly as in Git.
Six namespaces are accepted and any other name is refused:

| Namespace | Points at | Meaning |
|---|---|---|
| `heads/*` | a `run` | mainline work |
| `experiments/*` | a `run` | branches; the only refs MCP writes |
| `promotions/*` | a `run` | release gates |
| `annotations/*` | an `annotation` | versioned metadata for one run |
| `tags/*` | any object | labels |
| `remotes/*` | any object | remote-tracking |

Ref updates are **compare-and-swap**: you say which value you expect to replace,
and a stale expectation is refused rather than silently overwriting another
writer. `tine promote` is the visible case — it defaults to *expect no existing
ref*, so moving an existing promotion requires `--expected-old`, and there is no
`--force`.

A **reflog** records where a ref has pointed, so a ref move is auditable rather
than merely current.

## Verify

Three different things are called verification; they prove different things.

- **Integrity** (`tine verify <run>`) recomputes the artifact digest. It detects
  corruption and most edits, but anyone who can edit the file can recompute it.
  It is a checksum, not a claim about who produced the run.
- **Authenticity** (`tine verify <run> --pubkey …` / `--key-env …` /
  `--require-signature`) checks an Ed25519 or HMAC signature over a canonical
  *signed view* recomputed from content, so a body edit plus a digest rewrite
  still fails. `tine verify` fails **closed** the moment any key-material or
  signature flag is present.
- **Structural verification** (`tine fsck --repo .`) recomputes every object id,
  validates envelope canonicality, typed parent/causal links, shallow
  boundaries, refs, and the event DAG, and detects cycles.

Signature semantics — what a signature does and does not prove — are in
[SECURITY_MODEL.md](SECURITY_MODEL.md).

## Fork

A fork branches from a chosen point and keeps everything before it. That is the
whole product thesis: an agent run that went wrong at step 7 does not have to be
re-run from step 0.

- `tine fork <run> --from-step N` branches a **file** and writes a new artifact.
  `--from-step` takes a decimal index, a full step id, or a unique prefix.
- `tine repo-fork <ref-or-oid> --from-event <oid> --ref <REF>` branches a **run
  object** and moves a repository ref. `--ref` is required and has no default:
  the ref you write is always your decision.

The two identity schemes differ on purpose. A v3 run id is a **content hash**,
so two identical forks deduplicate to one object. A v2 fork id names the fork
**act** — derived from the lineage, the retained slice, the branch, the declared
intent, and a recorded nonce, stored in `metadata.fork` and provable with
`verify_fork_id` — so forking the same point twice yields two distinct runs
instead of colliding. Both are digests, and a run id read from an untrusted
artifact never steers an output path.

## Replay

Replay re-derives a run from what was recorded.

- `--mode cache` reuses the recorded steps. Deterministic and free.
- `--mode rerun` re-executes them against the live model or harness.
- `--verify` is the proof obligation: replay into a temporary directory, read
  the artifact back, derive the replay a second time from the source, and
  compare. Exit **0** when reproduced, **1** on drift or a source that will not
  load. It writes nothing unless `--save` names a destination.
- `--inspect` previews exactly the steps a replay retains — the ancestors of
  `--from-step`, which is the same slice `--verify` expects.

`--ignore-cost-drift` lets cost/usage/billing differences alone still pass;
**structural drift always fails**. With `--harness` the run is re-executed twice
and the two artifacts compared, which is how a nondeterministic agent is caught.

## Diff

Diff is semantic, not textual. It reports the events the two runs share, the
events only one side has, and — for divergent events at the same position — the
fields that changed, alongside cost, latency, tool path, usage, billing,
artifacts, and evaluation scores.

The exact common/only sets use object identity. The `changed` pairs are a
sequence-position comparison of divergent events, not a causal merge alignment.
Transcript line merging is not an operation OpenTine offers, and that is a
decision rather than a gap: agents select, compose, fork, resume, evaluate,
attest, and promote run graphs instead.

`tine diff` and `tine replay --verify` publish the same `drift` object
(`structural`, `accounting`, `only_source`, `only_replay`) from one builder.
With `--exit-code`, `tine diff` follows `git diff`: **0** identical, **1**
different, never 2 — argparse keeps 2 for a usage error.

## Attest, evaluate, promote

Three ways to say something *about* a run without modifying it.

- **`tine attest`** attaches a signed-by-label claim — an approval, a provenance
  statement, a review.
- **`tine evaluate`** attaches immutable numeric scores from a named evaluator.
- **`tine promote`** moves a `promotions/<name>` ref: the release gate.

All three are content-addressed objects, so the judgement is itself provenance.
The `signer`/`evaluator` label is **self-asserted** unless the caller attaches
and independently verifies a signature — the CLI prints `unsigned` rather than
implying otherwise.

Promotion is deliberately not exposed to a model by default. Run content an MCP
client reads is untrusted input: text recorded inside a run can ask a model to
promote a run of an attacker's choosing, so creating a release gate stays an
operator action, and MCP fork/resume may write only `experiments/*`. The person
at the terminal is authenticated by having the shell; a model reached over MCP
is not. See [REPOSITORY.md](REPOSITORY.md#cli--mcp-parity-and-the-four-places-they-differ).

## Cost

Cost is computed from recorded token usage against a **pinned, signed pricing
catalog** — inference never performs a live price lookup. Calculations use
`Decimal`, exclusive input/output/cache/reasoning buckets, effective dates,
context thresholds, and service-tier modifiers.

A billing status is always attached, and it is honest about what is unknown:

| Status | Meaning |
|---|---|
| `complete` | every observed dimension has a pinned rate |
| `partial` | a known subtotal exists, but some dimension is unpriced |
| `unknown` | no exact price can be determined |
| `unmetered` | local API usage has no API charge (infrastructure may still cost) |

`cost` is always the known subtotal; it is never silently borrowed from another
provider or model. Provider APIs report token consumption, not the final
invoice, so a total is an estimate tied to the catalog it was read from — which
is why every `tine pricing … --json` payload names the `catalog_id` and
`catalog_hash` it answered from. See [PRICING.md](PRICING.md).

## Vocabulary

| Term | Meaning |
|---|---|
| **tine** | a prong of a fork; the file extension and the CLI command |
| **run** | one agent execution, as a DAG |
| **step** | a v2 node: `think`, `tool`, `model`, `done`, `error` |
| **event** | a v3 node: `model`, `tool`, `human`, `policy`, `approval`, `subagent`, `error` |
| **object** | an immutable v3 record: `blob`, `event`, `run`, `attestation`, `annotation` |
| **oid** | an object id, `TYPE:sha256:HEX` |
| **ref** | a mutable name pointing at an object, moved by compare-and-swap |
| **reflog** | the recorded history of one ref's values |
| **manifest** | recorded conditions: code, environment, policy, budget, pricing |
| **pack** | a deterministic bundle of objects, for transport |
| **shallow** | a repository fetched with a depth bound; operations past the boundary refuse |
| **attestation** | a content-addressed claim about a run |
| **drift** | the structural or accounting difference a verify/diff reports |

## Next

- [GETTING_STARTED.md](GETTING_STARTED.md) — run these ideas end to end.
- [CAPTURE.md](CAPTURE.md) — get an existing agent into this model.
- [API.md](API.md) — the Python names for everything above.
- [TINE_FORMAT.md](TINE_FORMAT.md) — exact v2 fields and the signed-payload boundary.
- [REPOSITORY.md](REPOSITORY.md) — exact v3 objects, packs, and the remote protocol.
- [SECURITY_MODEL.md](SECURITY_MODEL.md) — trust boundaries and threat model.
