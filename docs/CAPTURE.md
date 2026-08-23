# Capture the agent you already have

You do not have to rewrite an agent to put it under provenance. Every on-ramp
below produces the same thing — a run of `TraceEvent`s, content-addressed, that
`tine show`, `tine repo-diff`, `tine replay --verify`, and `tine export` all
understand.

| Your situation | The on-ramp | Timing |
|---|---|---|
| Anything emitting OTel GenAI spans | `tine import --format otel-json` | after the fact |
| A serialized framework log | `tine import --format langchain\|llamaindex\|autogen\|crewai\|openai-agents` | after the fact |
| Your own event stream | `tine import --format jsonl`, or `Recorder` in Python | either |
| LangChain / LangGraph | `OpenTineCallbackHandler` | **live** |
| An agent CLI (codex, claude-code, …) | `tine run --harness <name>` | **live** |
| A single model call | `tine run --model <provider>[:model]` | **live** |
| A local OpenAI-compatible server | `tine run --model vllm\|lmstudio\|sglang\|…` | **live** |
| Getting it back out | `tine export` | — |

## 1. OpenTelemetry GenAI: the universal path

This is the one that generalizes, and it is the model-agnostic on-ramp: it needs
no OpenTine adapter, no provider key, and no rate card. OpenTine reads the
OpenTelemetry GenAI semantic conventions directly, so a producer of GenAI spans
is a supported source with OpenTine never present at runtime:

- native OpenTelemetry GenAI instrumentation,
- **OpenLLMetry** (Traceloop) instrumentations,
- **OpenInference** (Arize) instrumentations,
- anything a collector already receives, dumped with the file exporter.

Two formats read that world:

```bash
# One complete OTLP/JSON export document (a resourceSpans envelope),
# a {"spans": [...]} wrapper, or a single span object.
tine import trace.json --format otel-json --save run.tine

# A JSON array of GenAI span objects, or one span per line.
tine import spans.jsonl --format otel-spans --repo . --ref heads/main
```

Message content is not spelled the same way by any two producers, so the
importer reads **four** shapes, in this order per side — a span carrying its
prompt one way and its completion another still gets both:

1. the classic v1.27.0 attributes `gen_ai.prompt` / `gen_ai.completion`;
2. GenAI span events and log records — `gen_ai.system.message`,
   `gen_ai.user.message`, `gen_ai.assistant.message`, `gen_ai.tool.message`, and
   `gen_ai.choice` — read from `events`, `logs`, or `logRecords`;
3. the structured v1.36.0 arrays `gen_ai.input.messages` /
   `gen_ai.output.messages`;
4. flattened indexed attributes: OpenLLMetry's `gen_ai.prompt.{i}.*` /
   `gen_ai.completion.{i}.*`, then OpenInference's `llm.*_messages.{i}.*`.

Everything collapses to one `{"messages": [{"role", "content"}, …]}` shape, and
anything the readers do not claim stays on the event's attributes rather than
being dropped.

The importer also accepts camelCase and snake_case span keys and decodes typed
`AnyValue` attributes. Every `gen_ai.usage.*` counter is preserved — input,
output, cache read, both cache-write TTLs, reasoning, and total — so a cached,
reasoning step keeps its numbers. `gen_ai.system` / `gen_ai.provider.name` is
read onto the step as its `provider`, so an imported trace carries the identity
half of its cost and can be priced afterwards — `--price` on the import, or
`tine price <run>` at any later date. Span links become causal edges;
`parentSpanId` becomes the parent edge.

`SOURCE` may be `-` to read stdin, so a collector export can be piped straight
in:

```bash
cat otel-dump.json | tine import - --format otel-json --repo . --ref heads/main
```

At least one destination is required. `--save PATH` writes a portable v2 `.tine`
artifact and refuses an existing file without `--force`; `--repo PATH` records
into a v3 repository and advances `--ref` (default `heads/main`). Both may be
given. `--ref` without `--repo` is refused rather than ignored.

`python examples/otel_interop.py` runs this path offline, end to end, and then
exports the imported run back out.

## 2. Serialized framework logs

If a framework wrote records rather than spans, name the framework. These
importers are deliberately best-effort: they normalize the common serialized
shapes, and a record they cannot read is skipped rather than guessed at.

```bash
tine import agent.log      --format langchain      --save run.tine
tine import events.json    --format llamaindex     --save run.tine
tine import conversation.jsonl --format autogen    --save run.tine
tine import crew.json      --format crewai         --save run.tine
tine import trace.jsonl    --format openai-agents  --save run.tine
```

Each framework's own id fields are mapped to the span model: LangChain's
`run_id`/`parent_run_id`/`name`, LlamaIndex's `id_`/`parent_id`/`event_type`,
AutoGen's `id`/`parent_id`/`sender`, CrewAI's `id`/`parent_id`/`agent`, and
OpenAI Agents' `span_id`/`parent_id`/`type`.

## 3. Your own event stream

If you already emit structured events, write them as one JSON object per line
and import them as OpenTine `TraceEvent` records:

```bash
tine import events.jsonl --format jsonl --repo . --ref heads/main
```

Recognized keys are `kind`, `timestamp` (or `time`/`ts`), `trace_id` (or
`run_id`), `span_id` (or `id`), `parent_span_id` (or `parent_id`),
`causal_span_ids`, `actor`, `model`, `cost`, `duration` (or `latency`), `inputs`
(or `input`), `outputs` (or `output`), `usage`, `billing`, and `attributes`.
`kind` is one of `model`, `tool`, `human`, `policy`, `approval`, `subagent`, or
`error`.

In Python the same thing is a `Recorder`, which is what every path above ends in:

```python
from opentine import Recorder, Repo, TraceEvent

recording = Recorder.start(Repo.open("."), ref="heads/main", prompt="…")
recording.append(TraceEvent(
    kind="model", timestamp=0, trace_id="trace", span_id="model-1",
    model="kimi-k3", inputs={"prompt": "hello"}, outputs={"text": "hi"},
    usage={"input": 12, "output": 3},
))
run_id = recording.finalize()
```

Record a failed step as an `error` event rather than dropping it, so a partial
run stays inspectable. `Recorder.start` captures code, dirty patch, and
environment manifests by default; pass `capture=False` to skip that.
`python examples/v3_repository.py` is a complete worked version.

## 4. Live capture: LangChain and LangGraph

Importing a serialized log is after the fact and only as complete as whatever
the framework chose to write down. The `langchain` extra records the run *as it
happens*, through langchain-core's callback protocol — which LangChain and
LangGraph both dispatch, so one handler covers both:

```bash
pip install "opentine[langchain]"
```

```python
from opentine.integrations.langchain import OpenTineCallbackHandler
from opentine.repository import Repo

handler = OpenTineCallbackHandler(Repo.init("runs"), ref="heads/main")
graph.invoke({"question": "…"}, config={"callbacks": [handler]})
run_id = handler.run_id      # one .invoke() is one finalized v3 run
```

The callback `run_id` becomes the span id, `parent_run_id` the parent edge, the
run's `name` the actor, and `LLMResult` token usage the run's usage — the same
mapping the post-hoc importer applies, through the same `TraceEvent` schema and
the same `Recorder`. Nothing in `opentine.integrations` is imported by
`import opentine`, so the extra is needed only to *use* the handler.

By default a fault in provenance capture is logged and survived rather than
killing the agent run it observes, matching langchain's own default. Pass
`raise_error=True` to make a refusing repository fail loudly.

CrewAI has no live adapter: its event bus identifies work by object reference
rather than by a run/parent id pair, so inferring parentage would produce
plausible but wrong causal edges. CrewAI logs are imported post hoc instead.

## 5. Live capture: agent CLIs

`tine run --harness` wraps an external agent CLI and records its steps:

```bash
tine run --harness codex --prompt "Inspect this repo" --save run.tine
tine run --harness kimi-code --prompt "Summarize README.md" --save run.tine
tine run --harness generic --harness-command "agent run" --prompt "Fix tests"
```

The bundled harness names are `claude-code`, `codex`, `cursor`, `gemini`,
`generic`, `grok`, `hermes`, `kimi-code`, `openclaw`, `opencode`, and `pi`. Use
`generic` with `--harness-command` (and repeatable `--harness-arg`) for anything
not on that list.

Process harnesses default to a one-hour wall timeout, a 4-million-character
total output ceiling, and 10,000 parsed events; override them with
`--harness-timeout`, `--harness-max-output`, `--harness-max-events`, and
`--harness-max-line-bytes`. Harnesses do not inherit the parent environment by
default: `--harness-login-env` forwards a fixed set — `PATH`, `HOME`, the
platform config/data/cache directories, and the harness's own login variables —
and `--harness-env NAME` (repeatable) adds named variables to *that* forwarded
set, so it only has an effect alongside `--harness-login-env`. Long runs can
checkpoint with `--autosave PATH` plus `--autosave-interval N` or
`--autosave-seconds T`.

Because a harness re-executes real work, it is also how nondeterminism gets
caught: `tine replay <run> --verify --harness <name>` runs it twice and compares
the two artifacts.

## 6. Live capture: a single model call

For one call with no framework at all:

```bash
tine run --model anthropic --prompt "Explain the current branch"
tine run --model openai:gpt-5.6 --prompt "…" --save run.tine
```

Any OpenAI-compatible server you already run locally is one `tine run --model`
away — no key, no Python, no rate card:

```bash
tine run --model vllm:served-model --prompt "…"   # http://localhost:8000/v1
tine run --model lmstudio --prompt "…"            # http://localhost:1234/v1
tine run --model ollama:llama3.1:8b --prompt "…"  # native adapter
```

`jan`, `koboldcpp`, `litellm`, `llama-cpp-python`, `llamacpp`, `lmstudio`,
`localai`, `mlx-lm`, `nvidia-nim`, `sglang`, `tensorrt-llm`, `tgi`, `unsloth`,
and `vllm` each resolve to the localhost URL their server conventionally listens
on; a server on a different port or an exact nonstandard prefix is the Python
`LocalOpenAICompatible(host=…)`/`base_url=…` form instead. Local API usage is
recorded `unmetered`, so these runs are captured, verified, and diffed like any
other — they just carry no dollar figure.

See [GETTING_STARTED.md](GETTING_STARTED.md#2-your-first-captured-run-with-no-code)
for the provider list and the exclusivity rules.

## 7. Getting it back out

Capture is not a one-way door. `tine export` renders any run as GenAI spans in
the same shape `--format otel-json` reads, so import and export are inverses:

```bash
tine export run.tine --output spans.json
tine export run.tine --endpoint http://127.0.0.1:4318 --service-name my-agent
```

Spans carry `gen_ai.operation.name`, request/response model, nanosecond
start/end times, trace/span/parent ids, links for causal edges, and a span kind
per step (a model call is `CLIENT`, in-process work is `INTERNAL`). Content goes
out **twice** so one document renders everywhere: `gen_ai.prompt` /
`gen_ai.completion` for readers that know the v1.27.0 conventions, and the
structured `gen_ai.input.messages` / `gen_ai.output.messages` arrays that
current backends such as Arize Phoenix and Langfuse render, with the scope's
`schemaUrl` naming the v1.36.0 conventions. Cost has no GenAI convention, so it
travels under the one documented `opentine.cost_usd` attribute (billing under
`opentine.billing`), and the importer reads both back: a run exported priced
imports priced, with the amount carried as the exact decimal string.

Practical notes for a real backend:

- The push sends `Content-Type: application/json` and nothing else — there is no
  flag for authorization headers. For a backend that needs credentials (Langfuse
  Cloud, a hosted vendor endpoint), point `--endpoint` at a local OpenTelemetry
  Collector and let the collector's exporter attach them.
- A cleartext push is refused unless the endpoint host is a **literal loopback
  IP** — `127.0.0.1` or `[::1]`, not the name `localhost` — or
  `--allow-insecure` is passed. A run carries prompts and completions.
- `/v1/traces` is appended unless the endpoint already ends there, so a base
  endpoint like `http://127.0.0.1:4318` is enough.
- Export is read-only over provenance: the artifact is never rewritten.

In Python the same conversion is two functions:

```python
from opentine import Repo, to_otel_genai, to_otel_genai_document

repo = Repo.open(".")
spans = to_otel_genai(repo.load_run("heads/main"))
document = to_otel_genai_document(repo.load_run("heads/main"), service_name="agent")
```

Both accept a `TraceEvent`, an iterable of them, or anything with `.steps` — a
v2 `Run`, a loaded `.tine` file, or a v3 repository run.

## What capture does *not* do

Redaction is typed and path-aware and runs before canonicalization and hashing,
but no automatic redactor can prove arbitrary prose is secret-free. Review
free-form model and tool output before sharing a run. The v2→v3 migrator keeps
the original artifact byte-exact as a legacy blob, so it can retain source
secrets and should be reviewed before synchronization. See
[SECURITY_MODEL.md](SECURITY_MODEL.md).

## Next

- [CONCEPTS.md](CONCEPTS.md) — what an event, a digest, and a ref actually are.
- [GETTING_STARTED.md](GETTING_STARTED.md) — the end-to-end walkthrough.
- [REPOSITORY.md](REPOSITORY.md) — v3 objects, packs, remotes, and MCP.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md#tine-import-reports-no-trace-events-found)
  — when an import finds no events.
