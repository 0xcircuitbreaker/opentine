# Capture the agent you already have

You do not have to rewrite an agent to put it under provenance. Every on-ramp
below produces the same thing — a run of `TraceEvent`s, content-addressed, that
`tine show`, `tine repo-diff`, `tine replay --verify`, and `tine export` all
understand.

Advanced verbs appear here in their 0.16 group spelling (`tine repo …`, `tine share …`,
`tine trust …`, `tine agent …`); the older top-level spellings such as `tine fsck` or
`tine promote` still work unchanged. The full mapping is in [CLI.md](CLI.md).

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
reasoning step keeps its numbers. Both readings in the wild are understood: the
current conventions' `gen_ai.usage.cache_read.input_tokens`,
`cache_creation.input_tokens` / `cache_write.input_tokens` and
`reasoning.output_tokens` are sub-counts *included in* `input_tokens` /
`output_tokens`, and are subtracted back out so a cached token is billed at the
cache rate; the older `cache_read_input_tokens`-style spellings (what OpenTine
itself exported through 0.8.1) are exclusive buckets and are read as such. An
`invoke_agent` / `create_agent` / `invoke_workflow` span becomes a `subagent`
step: its counters aggregate the model calls beneath it, so pricing it as well
would bill them twice. Only when no span beneath it reports usage — a remote
agent — is it billed as the model call it is. `gen_ai.system` / `gen_ai.provider.name` is
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

Provider spellings from the semantic-convention registry are mapped onto the
catalog's ids at import — `gcp.gemini` / `gcp.vertex_ai` / `gcp.gen_ai` →
`google`, `x_ai` → `xai`, `mistral_ai` → `mistral`, `aws.bedrock` → `bedrock`,
`azure.ai.openai` / `azure.ai.inference` → `foundry`, and LangChain's
`google_genai`, `mistralai`, `azure_openai`, … likewise — so those calls price
instead of reading `unknown`. The original attribute stays on the span.

**Agent CLI telemetry.** Claude Code (`CLAUDE_CODE_ENABLE_TELEMETRY=1`, plus
`CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1` for traces), Codex (`[otel]` in
`config.toml`) and Gemini CLI (`telemetry.enabled`) export OTLP. Their traces
import with `--format otel-json`: Claude Code's spans carry bare
`input_tokens` / `output_tokens` / `cache_read_tokens` /
`cache_creation_tokens` and no `gen_ai.usage.*`, and each
`claude_code.llm_request` becomes a priced model step (`claude_code.interaction`
a human step, `claude_code.tool` a tool step, `tool.blocked_on_user` an
approval). Their richer log events import with `--format otel-logs`: Claude Code
`api_request` / `user_prompt` / `tool_result` / `tool_decision` / `api_error`,
Codex `codex.sse_event` (`response.completed`) / `user_prompt` / `tool_result`
/ `tool_decision`, and Gemini CLI `gemini_cli.api_response` / `user_prompt` /
`tool_call` / `api_error` and `gen_ai.client.inference.operation.details`; each
becomes a priced event, chained per session in time order. The event cap is
enforced while records are read (at most 400,000 raw log records), so an
oversized file is refused before any session chain is built. `otel-json` also
accepts the collector file exporter's one document per line. `--format`
defaults to `auto`, which recognizes each of these by shape.

A message array serialized into one attribute string (`gen_ai.input.messages`)
is decoded only within the 16 MiB line bound and the structural-token budget;
beyond that it stays in the attributes as text and the event carries an import
warning.

`python examples/otel_interop.py` runs this path offline, end to end, and then
exports the imported run back out.

### Importing agent session logs

`tine import` also reads the session logs agent CLIs keep for themselves —
Claude Code (`~/.claude/projects/*/*.jsonl`), Codex
(`~/.codex/sessions/**/rollout-*.jsonl`), Gemini CLI
(`~/.gemini/tmp/*/chats/session-*.jsonl`, and the legacy `.json`) and Qwen Code
(`~/.qwen/projects/*/chats/*.jsonl`) — with `--format claude-code-transcript`,
`codex-session`, `gemini-session` or `qwen-session` (or `auto`):

```bash
tine import --from-default-location                         # the newest sessions on this machine
tine import latest --from-default-location --price --save run.tine
```

Each API call becomes a model step with its model, provider and exact usage, each
tool call a tool step, each prompt a human step, so `tine price` works on a
session that never ran under `tine run`. `CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
`GEMINI_CLI_HOME` and `QWEN_HOME` are honoured; a session-id prefix may stand in
for `latest`. A run imported from a session log records
`metadata.capture = {"method": "transcript-import", "source_format": …,
"agent_writable": true}`: the agent wrote that log and could have edited it, so
it is only as trustworthy as the machine it ran on. A Claude Code response
that a mid-stream tool result splits across lines is still one model step with
its usage counted once; a session id that is not short and id-shaped (at most
128 of `[A-Za-z0-9._:-]`) is stored as `session-<sha256 prefix>`, as are
per-record ids copied onto several events (`requestId`, `promptId`, `agentId`,
span ids). Tool names repeated on results are clipped to 256 characters, a
Codex call's arguments are recorded with its first output only, a Gemini tool
result attaches to one call even when ids repeat, and Gemini `$patch` merging
is linear. A record with an unexpected field type (`content`, `usage`,
`toolCalls`, `parts`, `logRecords`) is skipped and counted in
`opentine.import_warnings` on the run's first event instead of failing the
import, and an imported local run prices `unknown` (a provider label never makes
a call free: a model call imported without `--price` carries an explicit
`unknown` billing record, and every billing block the source carried is
dropped, whatever its status). The source's own `cost` figure is not the step's
cost either: it is kept as the `opentine.source_reported_cost` attribute, and the
catalog prices the step. The library path, `Recorder.import_events`, applies the
same rule unless called with `trusted_billing=True`.
Claude Code writes each subagent's transcript beside the session, in
`<session>/subagents/agent-*.jsonl`; those are imported with the session
(whether the format is detected or named), each
subagent's steps hung under the tool step that spawned it (at most 1,000 files,
real files only, each file on disk read once so hard links are skipped, the
session's byte budget charged before a file is parsed, and the event cap; any left out
are counted in `opentine.import_warnings`), and `--from-default-location` shows
how many each session has. Each API response is billed once across the whole session, so a
subagent transcript that repeats the response which spawned it is not counted
twice. Fast-mode and US-only calls (`usage.speed`,
`inference_geo`) keep their `fast` / `fast_us` / `us` tier, in transcripts and
in Claude Code OTel logs alike. OpenCode keeps its sessions
in a SQLite database whose schema is still changing and is not imported yet.

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
tine repo integrate harnesses --installed  # which agent CLIs are here, and what each records
tine run --harness codex --prompt "Inspect this repo" --save run.tine
tine run --harness gemini --prompt "Summarize README.md" --save run.tine
tine run --harness generic --harness-command "agent run" --prompt "Fix tests"
```

`tine repo integrate harnesses` lists every harness name, the command it runs, whether the CLI
is installed, and what a recorded run holds (`--installed`, `--json`). The
catalogued CLIs run in their documented headless JSON modes:

| Harness | Command | Model | Usage | CLI cost | Tools |
|---|---|---|---|---|---|
| `claude-code` | `claude -p --output-format stream-json --verbose` | yes | yes | yes | yes |
| `codex` | `codex exec --json --skip-git-repo-check` | with `--model` / `config.toml` | yes | no | yes |
| `gemini` | `gemini --output-format stream-json -p` | yes | yes | no | yes |
| `qwen-code` | `qwen --output-format stream-json -p` | yes | yes | no | yes |
| `pi` | `pi --mode json` | yes | yes | yes | yes |
| `hermes` | `hermes chat --oneshot --format stream-json -q` | yes | yes | no | yes |
| `openclaw` | `openclaw agent exec --json` | yes | yes | yes | summary |
| `opencode` | `opencode run --format json` | with `--model provider/model` | yes | yes | yes |
| `goose` | `goose run --output-format stream-json -t` | with `--model` / `GOOSE_MODEL` | yes | yes | yes |
| `copilot` | `copilot --output-format json -p` | yes | yes | multiplier only | yes |
| `cline` | `cline --json` | yes | yes | yes | no |
| `amp` | `amp --stream-json -x` | no | yes | no | yes |
| `cursor` | `agent --print --output-format stream-json` | display name | no | no | yes |
| `kimi-code` | `kimi --print --output-format stream-json -p` | with `--model` | no | no | yes |
| `openhands` | `openhands --headless --json -t` | no | no | no | yes |
| `vibe` | `vibe --output streaming --prompt` | with `--model` | if reported | no | yes |
| `grok`, `qoder` | `grok --no-auto-update --output-format streaming-json -p`, `qodercli --output-format stream-json -p` | JSON mode documented, schema not: read as Claude-compatible events (`unverified`) | | | |
| `droid`, `auggie`, `continue` | `droid exec --output-format json`, `auggie --print --output-format json`, `cn --format json -p` | final result only | | | |
| `aider`, `crush`, `kiro` | `aider --yes-always --no-pretty --message`, `crush run -q`, `kiro-cli chat --no-interactive` | text only | | | |

Use `generic` with `--harness-command` (and repeatable `--harness-arg`) for
anything else. `--harness-arg` values are inserted before a harness's prompt flag
(`-p`, `-q`, `--message`), so `--harness-arg --model --harness-arg
gemini-3.8-flash` reaches the CLI as an option. Not catalogued, because no
headless invocation could be confirmed from their docs: Kilo Code, iFlow CLI,
Z.ai ZCode.

Token conventions differ by CLI, and each harness converts to OpenTine's
exclusive buckets before recording: Gemini CLI and Qwen Code count cached tokens
inside `input_tokens` and keep thinking outside `output_tokens` (recorded as
`reasoning`); Goose and Copilot count cache inside input; Pi keeps reasoning
inside output; Codex reports the thread's running total, so each turn records its
own difference. Copilot's per-call `cost` is a premium-request multiplier,
recorded as `premium_multiplier` and never booked. A CLI's own dollar figure
(Pi, OpenCode, Cline per call; OpenClaw, Goose per run) is booked on that step;
`tine price` re-prices the model steps from the catalog independently.

On Windows, point `--harness-command` at an agent CLI's real executable, not
its npm `.cmd` shim: a batch file is refused any task holding
`" % ! ^ & | < >` or a line break, because `cmd.exe` would re-parse it.

`claude-code` runs `claude -p --output-format stream-json --verbose`, so a
captured run records what Claude Code actually did: one `model` step per API
call with the model, provider, and exact input-side token usage, one `tool`
step per tool call carrying its result, the true per-model output totals from
the final `result` event, and Claude Code's own reported cost on the closing
step. That makes the run priceable afterwards — `tine price <run>` re-prices it
from the signed catalog, independently of Claude Code's figure. Fast mode and
US-only inference are recorded as the `fast` / `fast_us` / `us` service tier.
Claude Code's own `total_cost_usd` is booked only when every model's
`costBasis` is `list`; otherwise it is kept as `reported_estimate_usd`. With a
non-Anthropic `ANTHROPIC_BASE_URL` the provider is `local-anthropic-compatible`
(loopback, unmetered) or `anthropic-compatible` (priced unknown), never
`anthropic`; Bedrock, Vertex and Foundry flags still win. Each run carries a
W3C `TRACEPARENT`, so Claude Code's own OTel trace shares the run's trace id,
recorded as `run.metadata.otel_trace_id`.

`codex` runs `codex exec --json --skip-git-repo-check`: one model step per turn
with exact usage (the model from `-m` / `--model` / `-c model=…` or
`~/.codex/config.toml`, profiles included; a `model rerouted` notice updates
it), and tool steps for commands, patches, MCP calls (`server.tool`), web
searches and collab calls. `--oss` / `--local-provider` record the local
provider.

**Whose words stdout is.** A text-mode agent CLI prints the model's answer, so
from 0.9.1 its stdout is recorded as text: a JSON-shaped line is parsed as an
event only when the command asks the CLI for JSON output — the last
`--output-format` / `--format` / `-o` / `--output` / `--mode` value on the
command line decides, or `--json`, and every catalogued harness asks for it by
default — and a currency amount in free text ("cost: $2.50") is booked only for
an operator-written `generic` command. Before, an answer containing a JSON line
or a dollar figure was recorded as a real tool step, error, or charge. stderr is
read on its own pipe and always recorded as text (`"stream": "stderr"`), never
as events or cost. Harness text output is masked across lines from a
private-key `BEGIN` marker to its `END` before it is parsed or stored (bodies
printed with line numbers, quoted, bulleted or indented included), and a failing
run's output tail is redacted before it is cut. A line that is a JSON document —
a JSON-mode CLI's own event — is never truncated as text, so a marker in a
model's answer cannot erase the event's usage, cost or tool calls; private-key
blocks inside its string values are masked and the event re-serialized before
it is buffered or parsed, and an event nested past 512 levels is recorded as
masked text. Each harness
names its own output-format options: Codex's `-o` is its last-message file, so
only `--json` switches the codex harness to JSON.

Process harnesses default to a one-hour wall timeout, a 4-million-character
total output ceiling, and 10,000 parsed events; override them with
`--harness-timeout`, `--harness-max-output`, `--harness-max-events`, and
`--harness-max-line-bytes`. Harnesses do not inherit the parent environment by
default: `--harness-login-env` forwards a fixed set — `PATH`, `HOME`, the
platform config/data/cache directories, and the harness's own login variables —
and `--harness-env NAME` (repeatable) adds named variables to *that* forwarded
set, so it only has an effect alongside `--harness-login-env`. Long runs can
checkpoint with `--autosave PATH` plus `--autosave-interval N` or
`--autosave-seconds T`. Without either, a harness run checkpoints at most every 2 seconds
and only after the run has grown by a quarter, so checkpoint work stays linear
in the output. Event subtrees nested deeper than 256 levels are recorded as
their compact JSON text with a `truncated_depth` marker, so a run can always
be saved.

Because a harness re-executes real work, it is also how nondeterminism gets
caught: `tine replay <run> --verify --harness <name>` runs it twice and compares
the two artifacts.

## 6. Live capture: a single model call

For one call with no framework at all:

```bash
tine run --model anthropic --prompt "Explain the current branch"
tine run --model openai:gpt-6.1-sol --prompt "…" --save run.tine
```

Any OpenAI-compatible server you already run locally is one `tine run --model`
away — no key, no Python, no rate card:

```bash
tine run --model vllm:served-model --prompt "…"   # http://localhost:8000/v1
tine run --model lmstudio --prompt "…"            # http://localhost:1234/v1
tine run --model ollama:llama3.1:8b --prompt "…"  # native adapter
```

Each local preset resolves to the localhost URL its server conventionally
listens on; `--base-url URL` (or `<PRESET>_BASE_URL`) points it at another port
or machine, and `--api-key-env NAME` (or `<PRESET>_API_KEY`) supplies a key for a
server that wants one. A hosted preset's own key never follows `--base-url` to
another host: `--base-url` on a hosted preset (Groq, DeepSeek, …) needs
`--api-key-env`. Local API usage is recorded `unmetered` — at capture and
when `tine price` re-prices the run — so these runs are captured, verified, and
diffed like any other; they just carry no dollar figure. Reasoning a server
leaves inline (`<think>…</think>`, `[THINK]…[/THINK]`, raw Harmony channels) is
split into reasoning for whole messages and streams alike. Ollama Cloud models
(`:cloud` tags, or `https://ollama.com`) are recorded as `ollama-cloud`, never
`unmetered`, and Ollama's cached prompt count is recorded as cache reads.

Anthropic-compatible and Responses-compatible servers are reachable from Python:
`Anthropic(base_url=…, provider=…, unmetered=…, cache_inclusive=…)` targets the
`/v1/messages` that Ollama, LM Studio, llama.cpp, vLLM and gateways serve, and
`OpenAI(base_url=…, provider=…, responses=True)` a compatible `/v1/responses`.
An explicit non-Anthropic `base_url` never receives `ANTHROPIC_API_KEY` /
`ANTHROPIC_AUTH_TOKEN`: pass `api_key=` or set `ANTHROPIC_COMPAT_API_KEY` (a
placeholder is sent otherwise). From the CLI, `tine run --model anthropic:MODEL
--base-url URL` records the run as `local-anthropic-compatible` (loopback,
unmetered) or `anthropic-compatible`. `ANTHROPIC_BASE_URL` set in the
environment keeps the SDK's own behaviour, as the operator's pairing of
endpoint and key.

See [GETTING_STARTED.md](GETTING_STARTED.md#2-your-first-captured-run-with-no-code)
for the provider list and the exclusivity rules.

## 7. Getting it back out

Capture is not a one-way door. `tine export` renders any run as GenAI spans in
the same shape `--format otel-json` reads, so import and export are inverses:

```bash
tine export run.tine --output spans.json
tine export run.tine --format atif --output trajectory.json
tine export run.tine --endpoint http://127.0.0.1:4318 --service-name my-agent
tine export run.tine --format intoto --agent me --output run.intoto.jsonl  # signed provenance
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

- The push sends `Content-Type: application/json` and `Accept-Encoding:
  identity`, and nothing else — there is no flag for authorization headers. For
  a backend that needs credentials (Langfuse Cloud, a hosted vendor endpoint),
  point `--endpoint` at a local OpenTelemetry Collector and let the collector's
  exporter attach them. The whole push has a 120 s deadline.
- A cleartext push is refused unless the endpoint host is a **literal loopback
  IP** — `127.0.0.1` or `[::1]`, not the name `localhost` — or
  `--allow-insecure` is passed. A run carries prompts and completions.
- `/v1/traces` is appended to the endpoint's path unless it already ends there
  (a query string stays a query string), so a base endpoint like
  `http://127.0.0.1:4318` is enough.
- Span ids have the OTLP shape: a native run's `traceId` (32 hex) and `spanId`
  (16 hex) are derived from the run and step ids, which ride along as
  `opentine.run_id`, `opentine.step_id`, `opentine.parent_step_id` and
  `opentine.causal_step_ids`; ids that already have the OTLP shape are kept.
  The importer restores the originals, so export → import keeps every id.
- The document is scrubbed of credential-shaped text before it is written or
  pushed, so an artifact written before 0.9.1 does not ship the tokens its
  writer kept.
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

## Which agents did what

Every recorded tool call is also an *action*: its verb (`exec`, `file.read`,
`file.write`, `file.delete`, `net`, `mcp`, `git`, `spawn_subagent`), the
programs it ran (through `sudo`, `env`, `bash -c` and `&&`/`;`/`|` chains), the
paths and hosts it named, the MCP server and tool, and the agent, session,
model and provider that made it — all from redacted content. Shell-side
writes count as `file.write` with their paths: redirects (`>`, `>>`, `&>`),
`tee`, `cp`/`mv`/`install`/`ln` destinations, `sed -i`, `dd of=`, `truncate`,
`touch` and `chmod`/`chown`/`chgrp` targets; the whole command is marked, so
`touched` can over-report a read in the same command line but never misses a
listed writer. A URL's host is kept even when redaction rewrote its
userinfo. `tine agent who`,
`tine agent actions`, `tine agent touched` and `tine agent audit --policy` query them through a
rebuildable SQLite index; MCP clients use `find_actions`. Gemini output
modalities (image, audio, video) and OpenAI audio/image token details are
recorded as separate usage dimensions, and OTel
`gen_ai.usage.<modality>.<side>_tokens` map to the same dimensions.

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

`--format atif` writes one ATIF-v1.8 trajectory document (to a file or stdout only; it cannot be pushed with `--endpoint`). `tine import` reads ATIF v1.0-v1.8 and OpenCode's `opencode.db` (read-only; `opencode.db::<session id>` picks a session).
