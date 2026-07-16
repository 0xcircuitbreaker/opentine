<p align="center">
  <img src="docs/assets/opentine-logo.svg" alt="opentine" width="120" />
</p>

<h1 align="center">opentine</h1>

<p align="center">
  <strong>Git for agent runs: record, verify, fork, compare, attest, and synchronize execution history.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/opentine/"><img src="https://img.shields.io/pypi/v/opentine?color=FF6900" alt="PyPI" /></a>
  <a href="https://github.com/0xcircuitbreaker/opentine/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-FF6900" alt="License" /></a>
  <a href="https://github.com/0xcircuitbreaker/opentine/actions"><img src="https://img.shields.io/github/actions/workflow/status/0xcircuitbreaker/opentine/ci.yml?color=FF6900" alt="CI" /></a>
  <img src="https://img.shields.io/badge/status-0.3.0%20beta-FF6900" alt="0.3.0 beta" />
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

```bash
pip install opentine
```

Provider SDKs are optional:

```bash
pip install "opentine[anthropic]"
pip install "opentine[openai]"
pip install "opentine[google]"
pip install "opentine[compat]"  # hosted OpenAI-compatible APIs
pip install "opentine[mcp]"
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
fail-closed `tine verify` options. See [TINE_FORMAT.md](TINE_FORMAT.md).

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
tine pricing show mistral ministral-3-14b --json
tine pricing check
tine pricing update ./new-signed-catalog.json
```

The signed bundled snapshot covers OpenAI, Anthropic, Kimi, DeepSeek, Gemini,
Grok/xAI, GLM/Z.AI, Qwen, Groq, Together, Mistral/Ministral, and OpenRouter
Hermes models. Direct Nous/Hermes pricing is marked dynamic and requires a local
overlay rather than pretending it is free. Unknown hosted models remain
runnable and visibly unpriced. `Budget(strict_cost=True)` stops before the next
call after billing becomes indeterminate.

See [PRICING.md](PRICING.md) for resolution order, provenance, and the catalog
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

Kimi()                            # kimi-k2.6, api.moonshot.ai
DeepSeek()                        # deepseek-v4-flash
GLM()                             # glm-5.2 / Z.AI global endpoint
Grok()                            # grok-4.5
Qwen()                            # qwen3.7-max international endpoint
Ministral()                       # ministral-3-14b
OpenRouter()                      # nousresearch/hermes-4-70b
Hermes()                          # direct Nous; local price overlay expected
```

`GLM_REGION=china` (or a legacy dotted GLM key) selects the BigModel China
endpoint and provider identity `glm-cn`; add a regional catalog overlay rather
than applying Z.AI global USD rates to that endpoint.

OpenAI native calls use Responses API items, tool-call continuation state,
refusals, and final usage. Anthropic handles cache-write buckets and adaptive
sampling restrictions. Kimi omits unsupported temperature fields and preserves
reasoning continuation. Google extracts usage instead of reporting zero, and
Ollama retains token counts plus load/evaluation timing.

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

See [REPOSITORY.md](REPOSITORY.md) for object semantics and synchronization.

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
    model="kimi-k2.6", inputs={"prompt": "hello"}, outputs={"text": "hi"},
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
export TINE_REMOTE_TOKEN='development-token'
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
forward; other anchor recovery requires an exact `--reanchor-audit-head` value.
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

Filesystem, network, shell, Python, and harness execution use restrictive
policies. Harnesses do not inherit the parent environment by default. Review
free-form model/tool output before sharing: credential redaction is typed and
path-aware, but no automatic redactor can prove arbitrary prose is secret-free.
See [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Validation

```bash
uv sync --all-extras
uv run ruff check .
uv run ruff format --check .
uv run python scripts/check_architecture.py
uv run pytest tests -m "not live and not live_harness" -q
uv build --sdist --wheel --out-dir dist
uv run --with twine twine check dist/*
uv run python scripts/wheel_smoke.py
```

CI runs these gates on Linux, macOS, and Windows with Python 3.11–3.13. Live
provider and CLI-harness tests remain opt-in because they require credentials or
installed services.

## Documentation

- [CHANGELOG.md](CHANGELOG.md): release-level changes and compatibility.
- [TINE_FORMAT.md](TINE_FORMAT.md): portable v2 and repository v3 boundaries.
- [PRICING.md](PRICING.md): signed catalogs and billing semantics.
- [REPOSITORY.md](REPOSITORY.md): objects, packs, migration, remote, and MCP.
- [SECURITY_MODEL.md](SECURITY_MODEL.md): trust, redaction, signing, and remote security.
- [SUPPORT.md](SUPPORT.md): supported runtimes and support levels.

## License

Apache-2.0. See [LICENSE](LICENSE).
