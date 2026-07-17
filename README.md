<p align="center">
  <img src="https://raw.githubusercontent.com/0xcircuitbreaker/opentine/v0.3.0/docs/assets/opentine-logo.svg" alt="OpenTine" width="120" />
</p>

<h1 align="center">OpenTine</h1>

<p align="center">
  <strong>Git for agent runs: record, verify, fork, compare, attest, and synchronize execution history.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/opentine/"><img src="https://img.shields.io/pypi/v/opentine?color=d4a574" alt="PyPI" /></a>
  <a href="https://github.com/0xcircuitbreaker/opentine/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-d4a574" alt="License" /></a>
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
pip install "opentine[all,mcp]" # every provider SDK plus MCP
```

## Portable v2 runs

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
fail-closed `tine verify` options. See [TINE_FORMAT.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/TINE_FORMAT.md).

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

See [PRICING.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/PRICING.md) for resolution order, provenance, and the catalog
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
tine object run:sha256:... --repo . --resolve-blobs
tine pack --repo . --output run.pack
```

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

The dependency-free trusted semantic kernel is kept at no more than 250
physical lines. CI also rejects every production Python module over 250 lines
and rejects upward imports into the kernel.

The v2→v3 migrator preserves the exact original artifact as a legacy blob,
records its original integrity/signature result, rebuilds redacted v3 objects,
and stores an old→new ID map. A legacy signature is explicitly scoped to the
legacy blob; it is never presented as a signature over new v3 objects. Bad
integrity or a requested signature failure is refused unless
`--allow-unverified` is explicit. Because the legacy blob is byte-exact, it can
retain source secrets and should be reviewed before synchronization.

See [REPOSITORY.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/REPOSITORY.md) for object semantics and synchronization.

## Live agent recording

`Recorder` records code, dirty patch, environment, policy, budget, and pricing
manifests, then appends immutable model/tool/human/policy/approval/subagent
events. Code-capture failures are recorded explicitly rather than appearing as
a clean repository:

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
AutoGen, CrewAI, and OpenAI Agents logs.
Search, minimal causal context slices, semantic diff, fork/resume, evaluation,
attestation, and promotion are also available as MCP tools.
Evaluation/approval attestations are content-addressed but their `signer` label
is self-asserted unless the caller attaches and independently verifies a signature.

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
See [SECURITY_MODEL.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/SECURITY_MODEL.md).

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
[RELEASING.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/RELEASING.md) for the required one-time configuration and release
checklist.

## Documentation

- [CHANGELOG.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/CHANGELOG.md): release-level changes and compatibility.
- [TINE_FORMAT.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/TINE_FORMAT.md): portable v2 and repository v3 boundaries.
- [PRICING.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/PRICING.md): signed catalogs and billing semantics.
- [REPOSITORY.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/REPOSITORY.md): objects, packs, migration, remote, and MCP.
- [SECURITY_MODEL.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/SECURITY_MODEL.md): trust, redaction, signing, and remote security.
- [RELEASING.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/RELEASING.md): trusted publication and release verification.
- [SUPPORT.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/SUPPORT.md): supported runtimes and support levels.
- [TROUBLESHOOTING.md](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/TROUBLESHOOTING.md): common install, provider, and verification failures.

## License

Apache-2.0. See [LICENSE](https://github.com/0xcircuitbreaker/opentine/blob/v0.3.0/LICENSE).
