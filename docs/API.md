# Public Python API

The supported surface is exactly `opentine.__all__` — every name below imports
as `from opentine import <name>`, and `tests/test_public_surface.py` fails if
that set changes without an edit to the test. Anything reachable only through a
private module (`opentine._…`) is an implementation detail.

This page is a map, one line per name, not generated autodoc. For behaviour, see
[CONCEPTS.md](CONCEPTS.md); for the CLI equivalent of each verb, see
[GETTING_STARTED.md](GETTING_STARTED.md).

## Running an agent

| Name | What it is |
|---|---|
| `Agent` | Executes a provider-neutral model/tool loop and returns a `Run`. `run_sync(prompt)` is the blocking form; `run`, `replay`, `resume` and their `_sync` twins complete the set. |
| `Model` | The adapter protocol every provider implements — `name`, `supports_tools`, `supports_thinking`, `complete`, `stream`. Anything satisfying it can be passed to `Agent`. |
| `Budget` | Limits a run by `max_cost`, `max_steps`, `max_duration`, or `max_usage`; `on_breach` is `"stop"` or `"raise"`, and `strict_cost=True` stops once billing becomes indeterminate. |
| `BudgetBreach` | Which dimension was breached, its limit, and what was incurred. |
| `BudgetExceeded` | Raised when an `on_breach="raise"` budget is exceeded. |
| `tool_schema` | Builds a tool-use schema from a plain function's signature and docstring. |

```python
from opentine import Agent, Budget
from opentine.models.anthropic import Anthropic

agent = Agent(model=Anthropic("claude-sonnet-5"), budget=Budget(max_cost=0.50))
run = agent.run_sync("Explain the current branch")
```

## The portable run graph (v2)

| Name | What it is |
|---|---|
| `Run` | One agent execution. `Run.load(path)` reads v1/v2, `run.save(path)` writes v2, and `add_step`, `fork`, `diff`, `ancestors`, `common_ancestor`, `cost_breakdown`, `total_cost`, `to_dict` operate on the graph. |
| `RunStatus` | `running`, `paused`, `completed`, `failed`. |
| `Step` | One node: kind, parent links, inputs, outputs, model/tool metadata, error, timing, cost, usage, billing. |
| `StepKind` | `think`, `tool`, `model`, `done`, `error`. |
| `Graph` | The `steps` mapping plus the stable `order` used for display. |
| `step_id` | Recomputes a step's content-addressed id. |
| `short_id` | The abbreviated display form of any id. |
| `FORMAT_VERSION` | The portable artifact version this build writes (`2`). |

## Comparing runs

| Name | What it is |
|---|---|
| `RunDiff` | The result of `run.diff(other)`: common ancestor, `only_a`, `only_b`, and `changed`. |
| `StepChange` | One divergent step pair and the fields that differ. |
| `FieldDelta` | One field's `before`/`after`, plus `changed_keys` for mappings. |

## Integrity and signatures

| Name | What it is |
|---|---|
| `IntegrityResult` | The verdict of `Run.verify_integrity(path_or_data)`: `ok`, algorithm, expected vs actual digest, reason. |
| `SignatureResult` | The verdict of `Run.verify_signature(...)`: `ok`, state, algorithm, key id, signer, signed-at, reason. |
| `SignatureError` | Raised when signing or verification cannot proceed. |
| `sign_artifact` | Signs an artifact dict with `hmac-sha256` or `ed25519`, returning the signed dict. |
| `verify_artifact` | Verifies one, given `hmac_key=`, `public_key=`, or explicit `trust_embedded=True`. |

Verification is fail-closed: ask for authenticity and a missing or bad signature
is a failure, never a downgrade to a checksum. See
[SECURITY_MODEL.md](SECURITY_MODEL.md).

## The v3 repository

| Name | What it is |
|---|---|
| `Repo` | The object database. `Repo.init(path)` / `Repo.open(path)`; `put`/`get` objects, `update_ref`/`read_ref`/`list_refs` (compare-and-swap), `log`, `diff`, `fork`, `context_slice`, `search`, `inspect`, `attest`, `promote`, `load_run`/`put_run`, `migrate_v2`, `pack`/`import_pack`, `fetch`/`push`, and `fsck`. |
| `Recorder` | Records a live run into a `Repo`: `Recorder.start(repo, ref=…)`, `append(event)`, `import_events(events)`, `finalize(status)`, plus `fork`, `resume`, `evaluate`, `approve`, `promote`. |
| `TraceEvent` | One normalized event — kind, timing, trace/span/parent ids, causal links, actor, model, inputs, outputs, usage, billing, attributes. Invalid metrics are refused at construction, not at write. |

```python
from opentine import Recorder, Repo, TraceEvent

repo = Repo.init("agent-history")
recording = Recorder.start(repo, ref="heads/main", prompt="…")
recording.append(TraceEvent(kind="model", timestamp=0, trace_id="t", span_id="s"))
run_id = recording.finalize()
assert repo.fsck().ok
```

`FsckResult` and `SemanticDiff` are returned by `Repo.fsck()` and `Repo.diff()`
and are importable from `opentine.repository` (or `opentine.repo`).

## Trace interoperability

| Name | What it is |
|---|---|
| `to_otel_genai` | Renders a run as a list of OpenTelemetry GenAI spans. Accepts a `TraceEvent`, an iterable of them, or anything with `.steps` — a v2 `Run`, a loaded `.tine` file, or `repo.load_run(ref)`. |
| `to_otel_genai_document` | The same spans wrapped in a complete OTLP/JSON export document; `service_name=` sets `service.name`. |

The importers live one level down, in `opentine.trace`, and are the exact
inverses: `otel_genai_events`, `jsonl_events`, `native_events`, and
`framework_events(records, framework)` for `langchain`, `llamaindex`, `autogen`,
`crewai`, and `openai-agents`. [CAPTURE.md](CAPTURE.md) covers all of them.

## Cost and billing

| Name | What it is |
|---|---|
| `Usage` | Normalized token counts: input, output, cache read, both cache-write TTLs, reasoning, total, plus provider extras. |
| `BillingResult` | A priced result: status, amount, known subtotal, and the `catalog_id`/`catalog_hash`/`rate_card_id` it was resolved against. |
| `CostBreakdown` | `run.cost_breakdown()`: totals plus `by_model`, `by_kind`, and `by_ref`. |
| `PricingCatalog` | A loaded catalog — its id, hash, cards, signed state, and provenance. |
| `RateCard` | One model's exact rates, effective dates, context thresholds, service modifiers, and currency. |

Billing status is one of `complete`, `partial`, `unknown`, or `unmetered`; see
[PRICING.md](PRICING.md).

## Indexing and search (legacy `.tine_runs`)

| Name | What it is |
|---|---|
| `RunIndex` | The file index behind `tine ls`/`search`/`stats`: `RunIndex.open(dir)`, `search`, `lookup`, `sync`, `reindex`, `update_from_file`. |
| `Query` | A parsed query — free text plus `tags`, `model`, `status`, and cost/date bounds. |
| `parse_query` | Parses `"tag:prod model:kimi cost:<0.5"` into a `Query`. |
| `QueryError` | Raised for a query that cannot be parsed. |

## Migration

| Name | What it is |
|---|---|
| `migrate_dict` | Returns a *new* dict migrated to the target format version; the input is never mutated. |
| `MigrationError` | Raised when an artifact cannot be migrated to the requested version. |
| `__version__` | The installed OpenTine version. |

## Beyond the root namespace

These are supported, documented modules that are deliberately **not** re-exported
at the package root — importing them should be an explicit decision:

| Import | Why it is separate |
|---|---|
| `opentine.models.anthropic` / `.openai` / `.google` / `.ollama` / `.compat` | Each lazy-imports its provider SDK; the root must stay installable with none of them. |
| `opentine.models.resolve_model("provider:model")` | The string-to-adapter resolver `tine run --model` uses. |
| `opentine.harnesses` | External agent-CLI harnesses. |
| `opentine.tools` | Bundled filesystem, shell, Python, web, and search tools, under restrictive policies. |
| `opentine.integrations.langchain.OpenTineCallbackHandler` | Needs `opentine[langchain]`; `import opentine` must never pull in a framework. |
| `opentine.repository`, `opentine.repo` | `Repo`, `FsckResult`, `SemanticDiff`, and the object-store internals. |
| `opentine.trace` | `Recorder`, `TraceEvent`, and the importer/exporter functions. |
| `opentine.remote` | The self-hosted remote service, stores, and identity/authorization seams. |
| `opentine.mcp_server`, `opentine.mcp_repository` | The MCP surface; needs `opentine[mcp]`. |
| `opentine.cli.main(argv)` | Runs one `tine` invocation in-process — what the examples and tests use. |
| `opentine.kernel` | The dependency-free trusted kernel: canonical encoding, typed ids, immutable envelopes. |

The policy configuration API — `PolicySet`, `FilesystemPolicy`, `NetworkPolicy`,
`ShellPolicy`, `PythonPolicy`, `RedactionPolicy`, and the `secure_profile` /
`dev_profile` / `isolated_profile` helpers — is reachable from `opentine.core`
but is **deliberately absent from the package root**: it is a configuration API
rather than a data type, and promoting it is a larger commitment than the
0.6.0 re-export batch made. `tests/test_public_surface.py` pins both halves of
that decision.

## Next

- [GETTING_STARTED.md](GETTING_STARTED.md) — the CLI walkthrough.
- [CONCEPTS.md](CONCEPTS.md) — what these types mean.
- [CAPTURE.md](CAPTURE.md) — ingestion and export.
- [REPOSITORY.md](REPOSITORY.md) — v3 object semantics in full.
