<p align="center">
  <img src="https://raw.githubusercontent.com/0xcircuitbreaker/opentine/v0.5.0/docs/assets/opentine-logo.svg" alt="OpenTine" width="120" />
</p>

<h1 align="center">OpenTine</h1>

<p align="center">
  <strong>Git for agent runs: record, verify, fork, compare, attest, and synchronize execution history.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/opentine/"><img src="https://img.shields.io/pypi/v/opentine?color=d4a574" alt="PyPI" /></a>
  <a href="https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-d4a574" alt="License" /></a>
  <a href="https://github.com/0xcircuitbreaker/opentine/actions"><img src="https://img.shields.io/github/actions/workflow/status/0xcircuitbreaker/opentine/ci.yml?color=d4a574" alt="CI" /></a>
  <img src="https://img.shields.io/badge/status-0.3.0%20beta-d4a574" alt="0.3.0 beta" />
</p>

A **tine** is the prong of a fork. OpenTine forks agent runs.

OpenTine 0.3.0 has two deliberately separate compatibility surfaces:

- Portable `*.tine` files remain format v2. Existing `Run`, `Agent`, signing,
  replay, and `total_cost` APIs continue to work.
- A `.tine/` repository stores verified v3 `blob`, `event`, `run`,
  `attestation`, and `annotation` objects, refs, reflogs, packs, and indexes.

The v3 repository compares agent behavior semantically; it does not line-merge
transcripts.

## Install

OpenTine 0.3.x supports Python 3.11 through 3.14.

```bash
pip install opentine
```

Provider SDKs are optional:

```bash
pip install "opentine[anthropic]"
pip install "opentine[openai]"
pip install "opentine[google]"
pip install "opentine[compat]"  # hosted and local OpenAI-compatible APIs
pip install "opentine[mcp]"
pip install "opentine[langchain]" # live callback capture for LangChain/LangGraph
pip install "opentine[crypto]" # compatibility alias only; see below
pip install "opentine[all,mcp]" # every provider SDK plus MCP
```

`all` installs the Anthropic, OpenAI, and Google SDKs; it does not include
`mcp` or `langchain`. Ollama needs no extra because it uses the core `httpx`
dependency.
`crypto` is retained for older installation instructions and installs nothing
new: `cryptography` is already a required core dependency, so Ed25519 signing,
signed pricing catalogs, and the encrypted reference remote work from a plain
`pip install opentine`.

Provider credentials come from the environment. `.env.example` shows the
provider API keys plus the search-tool, pricing, and self-hosted-remote settings
OpenTine reads; adapters additionally honour provider-specific `*_BASE_URL`
overrides and `GLM_REGION`.

## Quickstart

This example calls Anthropic, so it needs the `anthropic` extra and a key:

```bash
pip install "opentine[anthropic]"
export ANTHROPIC_API_KEY=sk-ant-...
```

Without the extra the first model call raises
`ImportError: pip install opentine[anthropic]`; without the key the provider
rejects the request. Swap in `opentine.models.openai`, `opentine.models.google`,
or `opentine.models.ollama` and the matching variable from `.env.example` to run
against something else.

```python
from opentine import Agent
from opentine.models.anthropic import Anthropic

agent = Agent(model=Anthropic("claude-sonnet-5"))
run = agent.run_sync("Explain the current branch")
run.save("result.tine")
```

```bash
tine show result.tine
tine verify result.tine
tine cost result.tine
tine fork result.tine --from-step 0 --save retry.tine
tine replay result.tine --mode cache --save replayed.tine
tine diff result.tine retry.tine
```

`Run.load()` reads v1 and v2, migrates v1 in memory, and writes v2. HMAC-SHA256
and Ed25519 signatures are implemented through `tine sign`, `tine keygen`, and
fail-closed `tine verify` options. See [TINE_FORMAT.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/docs/TINE_FORMAT.md).

## Universal usage and billing

Every built-in model adapter returns the compatible `text`, `tool_calls`, and
numeric `cost` fields plus normalized `usage` and explicit `billing` metadata.
`cost` is always the known subtotal; it is never silently borrowed from another
provider or model.

Billing status distinguishes:

- `complete`: all observed dimensions have pinned rates;
- `partial`: a known subtotal exists but at least one dimension is unpriced;
- `unknown`: no exact price can be determined;
- `unmetered`: local API usage has no API charge, though infrastructure can
  still cost money.

Calculations use `Decimal`, exclusive input/output/cache/reasoning buckets,
effective dates, context thresholds, and service-tier modifiers. Provider APIs
normally report token consumption—not the final invoice—so the result is an
estimate tied to the pinned catalog and local overlays.

Inference never performs a live price lookup. Inspect or update pricing only
through explicit commands:

```bash
tine pricing list --provider kimi
tine pricing show xai grok-4.5
tine pricing show mistral ministral-14b-2512 --json
tine pricing check
tine pricing update ./new-signed-catalog.json
```

The signed bundled snapshot covers OpenAI, Anthropic, Kimi, DeepSeek, Gemini,
Grok/xAI, GLM/Z.AI, Qwen, Groq, Together, Mistral/Ministral, and OpenRouter
Hermes models. Direct Nous/Hermes pricing is marked dynamic and requires a local
overlay rather than pretending it is free. Unknown hosted models remain
runnable and visibly unpriced. `Budget(strict_cost=True)` stops before the next
call after billing becomes indeterminate.

Current exact cards include GPT-5.6 Sol/Terra/Luna, Kimi K3 and K2.7 Code,
GLM-5.2, DeepSeek V4, Gemini 3.5, Grok 4.5, Qwen 3.7, and current
Mistral/Ministral families. Catalog coverage is intentionally curated rather
than an allowlist: any model identifier remains runnable, and models without an
exact effective card are reported as `unknown` instead of receiving a guessed
price.

See [PRICING.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/docs/PRICING.md) for resolution order, provenance, and the catalog
maintenance boundary.

## Model adapters

Native adapters:

```python
from opentine.models.anthropic import Anthropic
from opentine.models.google import Google
from opentine.models.ollama import Ollama
from opentine.models.openai import OpenAI

OpenAI("gpt-5.6")                 # native Responses API
Anthropic("claude-sonnet-5")
Google("gemini-3.5-flash")
Ollama("qwen3")                  # usage/timing retained; API is unmetered
```

Hosted OpenAI-compatible adapters use Chat Completions with provider-scoped
usage and prices:

```python
from opentine.models.compat import (
    DeepSeek, GLM, Grok, Groq, Hermes, Kimi, Ministral,
    Mistral, OpenRouter, Qwen, Together,
)

Kimi()                            # kimi-k3, api.moonshot.ai
DeepSeek()                        # deepseek-v4-flash
GLM()                             # glm-5.2 / Z.AI global endpoint
Grok()                            # grok-4.5
Qwen()                            # qwen3.7-max international endpoint
Ministral()                       # ministral-14b-2512
OpenRouter()                      # nousresearch/hermes-4-70b
Hermes()                          # direct Nous; local price overlay expected
```

`GLM_REGION=china` (or a legacy dotted GLM key) selects the BigModel China
endpoint and provider identity `glm-cn`; add a regional catalog overlay rather
than applying Z.AI global USD rates to that endpoint.

OpenAI native calls use Responses API items, tool-call continuation state,
refusals, and final usage. Anthropic handles cache-write buckets, reported
inference geography, and adaptive sampling restrictions. Kimi omits unsupported temperature fields and preserves
reasoning continuation. Google extracts usage instead of reporting zero, and
Ollama retains token counts plus load/evaluation timing.

### Local and generic compatible runtimes

OpenTine has native Ollama support and one exact-base OpenAI-compatible surface
for the broader local ecosystem. The named presets are conveniences, not
separate protocol forks:

```python
from opentine.models.compat import LMStudio, LocalOpenAICompatible, OpenAICompatible, SGLang

LMStudio("loaded-model")
SGLang("served-model")

# `base_url` is exact; it is never changed or given a second `/v1` suffix.
local = LocalOpenAICompatible(
    "served-model",
    base_url="http://localhost:3000/api",  # for example, Open WebUI
    api_key="local-secret",
    supports_tools=False,
    include_usage=True,
    extra_body={"chat_template_kwargs": {"enable_thinking": True}},
)

# Hosted gateways default to unknown billing, not local/unmetered billing.
gateway = OpenAICompatible(
    "provider/model",
    base_url="https://gateway.example/openai",
    api_key="gateway-secret",
)
```

`LocalOpenAICompatible(host=...)` appends `/v1` once; pass `base_url=...` for
an exact nonstandard prefix. `OpenAICompatible` and custom OpenAI endpoints do
not inherit ambient proxy settings, do not follow redirects, and never forward
`OPENAI_API_KEY` implicitly. Use `OPENAI_COMPAT_API_KEY` or an explicit key.
Configured provider endpoints are trusted infrastructure: SDKs can buffer a
provider response before OpenTine applies retained-content limits.

Common compatible endpoints are:

| Runtime | Typical exact base | OpenTine surface |
|---|---|---|
| LM Studio | `http://localhost:1234/v1` | `LMStudio` |
| vLLM / Unsloth | `http://localhost:8000/v1` | `VLLM` / `Unsloth` |
| llama.cpp | `http://localhost:8080/v1` | `LlamaCpp` |
| LocalAI | `http://localhost:8080/v1` | `LocalAI` |
| Jan | `http://localhost:1337/v1` | `Jan` |
| llama-cpp-python | `http://localhost:8000/v1` | `LlamaCppPython` |
| MLX-LM | `http://localhost:8080/v1` | `MLXLM` |
| NVIDIA NIM / TensorRT-LLM | `http://localhost:8000/v1` | `NvidiaNIM` / `TensorRTLLM` |
| SGLang | `http://localhost:30000/v1` | `SGLang` |
| Hugging Face TGI | `http://localhost:8080/v1` | `TGI` |
| Open WebUI | `http://localhost:3000/api` | exact `base_url` |
| LiteLLM Proxy | `http://localhost:4000/v1` | `LiteLLM`; may route paid APIs |
| llamafile | `http://localhost:8080/v1` | `LocalOpenAICompatible` |
| GPT4All | `http://localhost:4891/v1` | `LocalOpenAICompatible` |
| KoboldCpp | `http://localhost:5001/v1` | `KoboldCpp` |
| text-generation-webui | `http://localhost:5000/v1` | `LocalOpenAICompatible` |
| MLC-LLM and llama-swap | configured server base, usually `/v1` | `LocalOpenAICompatible` |

Model IDs, tool calling, reasoning fields, multimodal input, and usage reporting
depend on the loaded model, chat template, runtime version, and server flags.
Set `supports_tools=False` where needed and request `include_usage=True` only
when the server implements final stream usage. Local API cost is `unmetered` by
default; supply `rates=` to account for infrastructure. The `LiteLLM` preset
and `OpenAICompatible` deliberately default to unknown billing because a
gateway may route paid hosted APIs.

## V3 repository

```bash
tine init .
tine migrate-v3 result.tine --repo . --ref heads/main
tine fsck --repo .
tine repo-log heads/main --repo .
tine repo-fork heads/main --from-event event:sha256:... --ref experiments/alt --repo .
tine repo-resume heads/main --ref experiments/live --repo .
tine promote experiments/alt --name released --repo .
tine object run:sha256:... --repo . --resolve-blobs
tine pack --repo . --output run.pack
```

Every v3 MCP tool has a CLI verb and vice versa, and the map is a CI gate. The
two surfaces differ in exactly four documented places, all of them trust
decisions: `promote` is unconditional on the CLI but opt-in over MCP,
`repo-fork`/`repo-resume` are confined to `experiments/*` only over MCP (whose
threat model is model-chosen refs, not an operator), CLI `--json` receipts are a
superset of the MCP return, and the CLI refuses non-finite evaluation scores at
the argument door. See
[REPOSITORY.md](docs/REPOSITORY.md) for the table and the reasoning.

Python API:

```python
from opentine import Repo

repo = Repo.init(".")
blob = repo.put("blob", b"prompt")
assert repo.get(blob).body == b"prompt"
assert repo.fsck().ok
```

Object IDs are SHA-256 over object type, schema version, and canonical stored
bytes. Client-side redaction happens before canonicalization and hashing.
`fsck` recomputes IDs, validates typed links and refs, and detects event cycles.
Refs update with compare-and-swap semantics.

The two layers identify runs differently. A v3 repository id is a **content
hash**, so two identical forks deduplicate to one object. A v2 fork id names the
fork **act**: it is derived from the lineage, retained slice, branch, declared
intent, and a recorded nonce, stored in `metadata.fork`, and provable with
`verify_fork_id`, so forking the same point twice yields two distinct runs
instead of colliding. Both are always digests; a run id read from an untrusted
artifact never steers an output path.

The dependency-free trusted semantic kernel is kept at no more than 250
physical lines. `scripts/check_architecture.py` runs in CI and enforces three
gates: no production Python module may exceed 250 physical lines, `kernel.py`
may import nothing outside the standard library (the gate constrains what the
kernel depends on, not what depends on the kernel), and each of the `billing`,
`models`, `remote`, `repository`, and `trace` layers declares the layers it may
not import. `billing` may import none of `models`, `remote`, `repository`, or
`runtime`; `models` may import neither `remote` nor `repository`; `repository`
and `trace` may import neither `models` nor `remote`; and `remote` may not
import `models`.

The v2→v3 migrator preserves the exact original artifact as a legacy blob,
records its original integrity/signature result, rebuilds redacted v3 objects,
and stores an old→new ID map. A legacy signature is explicitly scoped to the
legacy blob; it is never presented as a signature over new v3 objects. Bad
integrity or a requested signature failure is refused unless
`--allow-unverified` is explicit. Because the legacy blob is byte-exact, it can
retain source secrets and should be reviewed before synchronization.

See [REPOSITORY.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/docs/REPOSITORY.md) for object semantics and synchronization.

## Live agent recording

`Recorder` records code, dirty patch, environment, policy, budget, and pricing
manifests, then appends immutable events of seven kinds: `model`, `tool`,
`human`, `policy`, `approval`, `subagent`, and `error`. Record a failed step as
an `error` event rather than dropping it, so a partial run stays inspectable.
Code-capture failures are recorded explicitly rather than appearing as a clean
repository:

```python
from opentine import Recorder, Repo, TraceEvent

repo = Repo.open(".")
recording = Recorder.start(repo, ref="heads/main")
recording.append(TraceEvent(
    kind="model", timestamp=0, trace_id="trace", span_id="model-1",
    model="kimi-k3", inputs={"prompt": "hello"}, outputs={"text": "hi"},
))
run_id = recording.finalize()
evaluation = recording.evaluate({"quality": 0.9}, evaluator="judge")
recording.promote("production")
```

Importers normalize OpenTine traces, JSONL, and OpenTelemetry GenAI spans or
complete OTLP/JSON exports, including camelCase keys and typed `AnyValue`
attributes. Framework importers
best-effort normalize common serialized shapes from LangChain, LlamaIndex,
AutoGen, CrewAI, and OpenAI Agents logs. `tine import` (see the CLI reference)
is the shell-level front end for exactly these importers.

### Live framework capture

Importing a serialized log is after the fact and only as complete as whatever
the framework wrote down. `opentine[langchain]` records a run *as it happens*
instead, through langchain-core's callback protocol — which LangChain and
LangGraph both dispatch, so one handler covers both:

```python
from opentine.integrations.langchain import OpenTineCallbackHandler
from opentine.repository import Repo

handler = OpenTineCallbackHandler(Repo.init("runs"))
graph.invoke({"question": "..."}, config={"callbacks": [handler]})
run_id = handler.run_id  # one .invoke() is one finalized v3 run
```

`run_id` becomes the callback `run_id` of each span, `parent_run_id` the parent
edge, the run's `name` the actor, and `LLMResult` token usage the run's usage —
the same mapping `framework_events` applies post hoc, recorded through the same
`TraceEvent` schema and the same `Recorder`. Nothing here is imported by
`import opentine`, so the extra is needed only to *use* the handler. CrewAI has
no live adapter yet: its event bus identifies work by object reference rather
than by a run/parent id pair, so its logs are still imported post hoc.

Export runs the other way with `to_otel_genai`, which renders any run — a v2
`Run`, a loaded `.tine` file, a v3 repository run from `repo.load_run(ref)`, or
a list of `TraceEvent`s — as GenAI spans in the same shape the importer reads,
and `to_otel_genai_document` wraps them in a complete OTLP/JSON export:

```python
from opentine import Repo, to_otel_genai_document

repo = Repo.open(".")
document = to_otel_genai_document(repo.load_run("heads/main"), service_name="agent")
```

Spans carry `gen_ai.operation.name`, request/response model, `gen_ai.prompt` /
`gen_ai.completion`, `gen_ai.usage.input_tokens` / `output_tokens`, nanosecond
start/end times, trace/span/parent IDs, and links for causal edges — the
OpenTelemetry GenAI semantic conventions as of v1.27.0, spelled once in
`opentine.trace._genai_semconv` so import and export cannot drift. Import and
export are inverses: re-importing exported spans yields the events they came
from. Cost and billing have no GenAI convention and travel under `opentine.*`
attributes, which the importer does not read back. Export is read-only over
provenance and writes nothing.
Search, minimal causal context slices, semantic diff, fork/resume, evaluation,
and attestation are also available as MCP tools. Promotion is still **not**
exposed to a model by default: `promote_run` is registered only when the host
passes `allow_promotion=True`, and the shipped `opentine.mcp_server` never
passes it. Run content an MCP client reads is untrusted input, so text recorded
inside a run can ask a model to promote a run of an attacker's choosing;
creating a release gate stays an operator action. For the same reason MCP
fork/resume may only write `experiments/*` refs. Mainline `heads/*`,
`promotions/*`, `tags/*`, and remote-tracking refs are operator-only, so an MCP
call that names `heads/main` is refused.

Operators get all three writes on the command line, which is the point: the
person at the terminal is authenticated by having the shell, a model reached
over MCP is not.

```bash
tine attest heads/main --signer release-manager --claim '{"kind":"approval"}'
tine evaluate heads/main --evaluator judge --score quality=0.9 --score safety=1
tine promote heads/main --name production            # creates the release gate
tine promote <run-oid> --name production --expected-old <current-oid>   # moves it
```

Each takes a ref name or a run oid, resolves it, and makes one engine call, so a
CLI-written attestation is byte-identical to the MCP one. `promote` defaults to
*expect no existing ref*: moving a promotion that already exists requires
`--expected-old` naming the value being replaced, and there is no `--force`.
Adding the CLI verb does not widen the MCP surface — `allow_promotion` stays
`False` — it just stops the operator having to write Python to do their job.
Evaluation/approval attestations are content-addressed but their `signer` label
is self-asserted unless the caller attaches and independently verifies a
signature, and the CLI has no flag that claims otherwise; it prints `unsigned`.

## Self-hosted remote

The minimal HTTP remote provides capability discovery, missing-object
negotiation, filtered/shallow fetch, resumable pack upload, and CAS ref updates.
The reference backend uses encrypted filesystem object storage and SQLite
metadata/audit records.

```bash
export TINE_REMOTE_TOKEN="$(openssl rand -hex 32)"
export TINE_KMS_KEY="$(openssl rand -base64 32)"
tine serve --root /srv/opentine --cert cert.pem --key key.pem
```

TLS is mandatory unless `--insecure-dev` is explicit. Static bearer tokens are
for development; OIDC, reader/writer/admin RBAC, tenant namespaces, KMS key
providers, authorization, retention, audit, and admission-policy interfaces are
pluggable. The repository and extension seams are the enterprise foundation;
the bundled WSGI server is a bounded reference deployment for development and
small self-hosted installations, not a turnkey HA service, hosted control plane,
or payment product.

Audit rows use a serialized HMAC chain and authenticated head outside SQLite;
legacy rows require explicit trust-on-migration and remain reported as
`legacy-unverified`. The reference app derives the audit key from its local KMS
master. A custom KMS adapter must provide stable external audit-key derivation
(or an explicit audit key); startup fails closed rather than falling back to a
key beside the database. Interrupted post-commit anchor writes heal one step
forward only after the committed row authenticates; a cross-process lock spans
the commit and checkpoint update. Other anchor recovery requires an exact
`--reanchor-audit-head` value.
Protect the audit key, checkpoint, and backups.

```bash
tine push https://runs.example --tenant team --repo .
tine clone https://runs.example ./clone --tenant team
```

## Harnesses and tools

OpenTine can capture external CLI agents:

```bash
tine run --harness codex --prompt "Inspect this repo" --save run.tine
tine run --harness kimi-code --prompt "Summarize README.md" --save run.tine
tine run --harness generic --harness-command "agent run" --prompt "Fix tests"
```

Process harnesses default to a one-hour wall timeout, 4-million-character total
output ceiling, and 10,000 parsed events. Override them with
`--harness-timeout`, `--harness-max-output`, `--harness-max-events`, and
`--harness-max-line-bytes`.

Filesystem, network, shell, Python, and harness execution use restrictive
policies. Tool schemas hide host-owned policy/resource parameters and runtime
dispatch rejects attempts by a model to override them; bind an explicit policy
in an application wrapper when enabling shell, Python, or filesystem writes.
Harnesses do not inherit the parent environment by default. Review
free-form model/tool output before sharing: credential redaction is typed and
path-aware, but no automatic redactor can prove arbitrary prose is secret-free.
Enabled shell/Python timeouts terminate the owned process group or Windows Job
Object and return only bounded partial output, with space reserved for stderr
diagnostics. These subprocess controls are resource boundaries, not an OS sandbox.
See [SECURITY_MODEL.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/docs/SECURITY_MODEL.md).

## CLI Reference

`tine` ships 27 subcommands. Each one prints its own `--help`, which is
authoritative when this page has drifted.

Portable `.tine` artifacts:

```text
tine run <script.py>                  Execute a Python script and save the Run it builds
tine run --harness codex --prompt P   Record an external CLI agent as a run
tine show <run>                       Pretty-print a run tree
tine cost <run>                       Show cost, tokens, and budget state
tine verify <run>                     Verify integrity, and authenticity when a key is given
tine sign <run> --key-env TINE_KEY    Sign an artifact (hmac-sha256 or ed25519)
tine keygen --out key --pub key.pub   Generate an Ed25519 keypair
tine fork <run> --from-step 3         Branch from a step and continue there
tine replay <run> --mode cache        Reuse recorded steps; --mode rerun re-executes
tine diff <run_a> <run_b>             Compare two runs step by step
tine resume <run>                     Continue a run whose manifest declares resume support
tine migrate <run> --in-place         Upgrade a legacy artifact to format v2
tine ls --tag prod --limit 20         List indexed runs from .tine_runs
tine search "tag:prod model:kimi"     Query that index
tine tag <run> --add prod             Add, remove, or list tags
tine reindex                          Rebuild .tine_runs/index.json
```

Interoperability:

```text
tine import <trace> --format otel-json --save run.tine
tine import - --format jsonl --repo . --ref heads/main
tine import agent.log --format langchain --save run.tine
```

`tine import` reads a foreign agent trace — `otel-json` (a complete OTLP/JSON
export document), `otel-spans` (a JSON array of GenAI spans, or one per line),
`jsonl` (OpenTine `TraceEvent` records), or one of `langchain`, `llamaindex`,
`autogen`, `crewai`, `openai-agents` — from a file or `-` for stdin, and records
it as an ordinary run. At least one destination is required: `--save PATH`
writes a portable v2 `.tine` artifact (refusing an existing file without
`--force`), `--repo PATH` records it into a v3 repository and advances `--ref`
(default `heads/main`). Both may be given. It prints the resulting run id.
Importing introduces no format change, and `--ref` is refused without `--repo`.

Machine-readable output:

```text
tine show|verify|ls|search|cost ... --json
```

`--json` replaces the rich rendering with exactly one JSON object on stdout;
without it the human rendering is unchanged. The fields of each object are
enumerated in `opentine/_cli_json.py` and are added to but never renamed within
a major version. A failure that stops the command producing a result stays human
text and a non-zero exit; a failure that *is* the result still comes out as the
object — `verify` reports a failed check as `"ok": false` and `cost` a breached
budget as `"over_budget": true`, both exiting 1.

Signed pricing catalogs:

```text
tine pricing list [--provider P] [--model M] [--at YYYY-MM-DD]
tine pricing show <provider> <model> [--at YYYY-MM-DD] [--json]
tine pricing check
tine pricing update <file-or-https-url> [--dest PATH]
```

V3 repository:

```text
tine init [path] [--bare]
tine migrate-v3 <run.tine> --repo . --ref heads/main [--allow-unverified]
tine fsck --repo . [--shallow]
tine repo-log [ref] --repo . [--limit N] [--json]
tine repo-show <ref-or-run-oid> --repo . [--json]
tine repo-diff <left> <right> --repo . [--exit-code] [--json]
tine repo-search [query] --repo . [--limit N] [--min-score S] [--model M] [--json]
tine context <event-oid> --repo . [--depth N] [--json]
tine repo-fork <ref-or-run-oid> --from-event <oid> --ref REF \
    [--model M] [--prompt P] [--policy JSON] [--repo .] [--json]
tine repo-resume <ref-or-run-oid> --ref REF [--repo .] [--json]
tine attest <ref-or-run-oid> --signer NAME (--claim JSON | --claim-file PATH) [--json]
tine evaluate <ref-or-run-oid> --evaluator NAME --score NAME=VALUE... [--json]
tine promote <ref-or-run-oid> --name NAME [--expected-old OID] [--json]
tine object <object-id> --repo . [--resolve-blobs]
tine pack --repo . --output run.pack [object-id ...]
```

A v3 verb takes a `repo-` prefix only where a legacy v2 verb already owns the
plain name — `show`, `search`, `diff`, `fork`, `resume`. `context`, `attest`,
`evaluate`, and `promote` have no v2 namesake and stay unprefixed. The two
families are different stores: `tine fork` branches a `.tine` file, `tine
repo-fork` branches a run object and moves a repository ref.

Self-hosted remote:

```text
tine serve --root DIR --cert cert.pem --key key.pem [--insecure-dev]
tine fetch <remote> --repo . [--tenant T] [--ref R] [--depth N]
tine push <remote> --repo . [--tenant T] [--ref R] [--remote-ref R]
tine clone <remote> <path> [--tenant T] [--ref R] [--depth N]
```

Flag details that are easy to get wrong:

- `--from-step` accepts a decimal step index, a full step id, or a unique
  step-id prefix.
- `--save PATH` chooses the output file. `run`, `fork`, and `replay` otherwise
  write `.tine_runs/<run-id>.tine`; `fork` and `replay` refuse to overwrite an
  existing `--save` destination unless `--force` is passed, and `keygen --force`
  overwrites an existing key file.
- `tine migrate` only previews unless `--in-place` or `--save` is given, and it
  drops any existing signature, so re-sign after migrating. Its single `--force`
  does two jobs: it overwrites an existing `--save` destination, and it waives
  the refusal to migrate a source whose integrity digest already failed.
- `tine sign` spells the destination guard `--overwrite`, not `--force`. Its
  separate `--force` waives the pre-sign integrity refusal, so it can produce a
  valid signature over a body that already failed verification.
- `tine verify` fails closed as soon as any of `--key-env`, `--key-file`,
  `--pubkey`, `--require-signature`, or `--trust-embedded-key` is present.
  With none of them it checks the integrity digest only.
- `tine search` understands `tag:`, `model:`, `status:`, `cost:`, `after:`, and
  `before:` predicates plus free text. `model:` matches a substring of the model
  id, `status:` is exact, and `cost:` accepts `>`, `>=`, `<`, `<=`, and
  `min..max`. `tine ls` exposes the same filters as flags, with `--since` and
  `--until` for the date bounds.
- `tine ls`, `tine search`, `tine tag`, and `tine reindex` read the legacy file
  index under `.tine_runs`, not a v3 repository.

## Validation

```bash
uv sync --locked --all-extras
uv run ruff check .
uv run ruff format --check .
uv run python scripts/check_architecture.py
uv run pytest tests -m "not live and not live_harness" -q
uv build --no-build-isolation --sdist --wheel --out-dir dist
uv run python scripts/check_release_inventory.py dist
uv run python -m twine check dist/*
uv run python scripts/wheel_smoke.py
```

CI runs these gates on Linux, macOS, and Windows with Python 3.11–3.14. Live
provider and CLI-harness tests remain opt-in because they require credentials or
installed services.

Tagged releases reuse one validated wheel/sdist pair for GitHub and PyPI. PyPI
publication uses OIDC Trusted Publishing behind the protected `pypi` GitHub
environment; no long-lived package-index token is stored. See
[RELEASING.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/docs/RELEASING.md) for the required one-time configuration and release
checklist.

## Documentation

- [CHANGELOG.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/CHANGELOG.md): release-level changes and compatibility.
- [TINE_FORMAT.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/docs/TINE_FORMAT.md): portable v2 and repository v3 boundaries.
- [PRICING.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/docs/PRICING.md): signed catalogs and billing semantics.
- [REPOSITORY.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/docs/REPOSITORY.md): objects, packs, migration, remote, and MCP.
- [SECURITY_MODEL.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/docs/SECURITY_MODEL.md): trust, redaction, signing, and remote security.
- [RELEASING.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/docs/RELEASING.md): trusted publication and release verification.
- [SUPPORT.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/SUPPORT.md): supported runtimes and support levels.
- [TROUBLESHOOTING.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/docs/TROUBLESHOOTING.md): common install, provider, and verification failures.

## Comparison

Git stores content-addressed source history. OpenTine stores content-addressed
agent execution provenance: objects are hashed, refs move under compare-and-swap,
and `fsck` recomputes every id. The analogy stops at merge: OpenTine compares
two runs semantically and reports the common ancestor and the divergent steps,
and it never line-merges transcripts.

LangGraph is the closest technical comparison for checkpoint replay and time
travel, but its checkpoints live inside the framework and its checkpointer
rather than in a standalone artifact another tool can read. An OpenTine run is a
portable `.tine` file or a `.tine/` repository with a documented format.

LangSmith is a stronger observability and evaluation product than anything here,
and CrewAI is an agent framework rather than a provenance store; OpenTine tries
to replace neither. It imports from that side of the fence instead:
`opentine.trace.importers` best-effort normalizes serialized LangChain,
LlamaIndex, AutoGen, CrewAI, and OpenAI Agents records, as well as OpenTelemetry
GenAI spans and OTLP/JSON exports, into the same event model, and
`opentine.trace.to_otel_genai` emits GenAI spans back out, so a verified run can
be shipped to whatever observability backend already runs beside it. What
OpenTine adds is the verification and branching layer underneath —
signed artifacts, fail-closed verification, forks, cache replay, semantic diff,
and pinned-catalog cost accounting — with an optional self-hosted remote rather
than a mandatory hosted backend.

## The Name

A **tine** is a prong of a fork. The `.tine` extension stores serialized run
graphs, and `tine` is the CLI command.

## Contributing

There is no separate contributor guide yet; this section is it.

```bash
git clone https://github.com/0xcircuitbreaker/opentine.git
cd opentine
uv sync --locked --all-extras
uv run pytest tests -m "not live and not live_harness"
uv run ruff check .
uv run ruff format --check .
uv run python scripts/check_architecture.py
```

That `pytest` marker selection is the one CI uses: `live` and `live_harness`
tests are deselected because they need provider credentials or an installed
agent CLI. Run the full local gate list from the Validation section above before
opening a pull request.

When Docker is available, `uv run python scripts/ci_docker.py` rehearses the
Ubuntu lane — lint, format check, the same deselected `pytest` run, `uv build`,
and the wheel smoke test — in one container per Python version, defaulting to
3.11, 3.12, and 3.13. `--python VERSION` is repeatable and replaces that default
set, so `--python 3.14` covers the remaining CI version. The preflight does not
run the architecture, release-inventory, or `twine` gates, and GitHub Actions
remains authoritative for macOS and Windows.

Report bugs on the
[issue tracker](https://github.com/0xcircuitbreaker/opentine/issues). Report
vulnerabilities through [SECURITY.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/SECURITY.md),
not a public issue.

## License

Apache-2.0. See [LICENSE](https://github.com/0xcircuitbreaker/opentine/blob/v0.5.0/LICENSE).
