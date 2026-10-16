# Agent-CLI dialect fixtures

Each file is built from the CLI's own documented event schema (reference docs or
the source/type definitions that emit it), fetched 2026-10-15, with invented but
self-consistent ids and token counts. They are not live captures: a fixture pins
the parser to the documented shape; when a CLI changes its stream, replace the
fixture with a real capture and keep the source line below current.

| Fixture | CLI / mode | Source |
|---|---|---|
| `gemini.jsonl` | `gemini --output-format stream-json -p` | github.com/google-gemini/gemini-cli `packages/core/src/output/types.ts`, `stream-json-formatter.ts`, `telemetry/uiTelemetry.ts` |
| `qwen-code.jsonl` | `qwen --output-format stream-json -p` | github.com/QwenLM/qwen-code `packages/cli/src/nonInteractive/types.ts`, `io/BaseJsonOutputAdapter.ts`; `docs/users/features/headless.md` |
| `cursor.jsonl` | `agent --print --output-format stream-json` | cursor.com/docs/cli/reference/output-format.md (example sequence) |
| `opencode.jsonl` | `opencode run --format json` | github.com/anomalyco/opencode `packages/cli/src/run/noninteractive.ts`, `packages/schema/src/token-usage.ts` |
| `pi.jsonl` | `pi --mode json` | github.com/earendil-works/pi `packages/coding-agent/docs/json.md`, `message-types.md` |
| `hermes.jsonl` | `hermes chat --oneshot --format stream-json -q` | github.com/NousResearch/hermes-agent `website/docs/reference/cli-commands.md`, `hermes_cli/stream_json.py`, `agent/usage_pricing.py` |
| `openclaw.json` | `openclaw agent exec --json` | github.com/openclaw/openclaw `docs/cli/agent.md` (envelope example, verbatim) |
| `kimi-code.jsonl` | `kimi --print --output-format stream-json -p` | github.com/MoonshotAI/kimi-cli `docs/en/customization/print-mode.md` (example, verbatim) |
| `goose.jsonl` | `goose run --output-format stream-json -t` | github.com/aaif-goose/goose `crates/goose-cli/src/session/mod.rs` (`StreamEvent`), `crates/goose/src/conversation/message.rs` |
| `amp.jsonl` | `amp --stream-json -x` | ampcode.com/docs/cli/streaming-json |
| `copilot.jsonl` | `copilot --output-format json -p` | docs.github.com Copilot CLI programmatic reference; github.com/github/copilot-sdk `nodejs/src/generated/session-events.ts` |
| `cline.jsonl` | `cline --json` | docs.cline.bot/cline-cli/cli-reference.md ("JSON Output for Agent Runs"), docs.cline.bot/sdk/reference/events.md |
| `openhands.jsonl` | `openhands --headless --json -t` | docs.openhands.dev/openhands/usage/cli/headless.md (example, verbatim) |

Flags of the locally installed `gemini` 0.41.2, `hermes`, `kimi` 1.47.0 and
`opencode` 1.18.31 were also checked against their `--help` output.
