# @opentine/capture

Capture agent runs made with the **Vercel AI SDK** (`ai`, v4 and v5 result
shapes) or the **OpenAI Agents SDK** (`@openai/agents`) into an OpenTine
repository, through the `opentine-hook/1` protocol
([docs/spec/hook-1.md](../../docs/spec/hook-1.md)) that `tine hook capture`
reads. No runtime dependencies: the adapters read the SDK's *result* object
structurally, so this package depends on neither SDK and works with any
version that keeps those field names.

```ts
import { generateText } from "ai";
import { fromVercelAI, deliver } from "@opentine/capture";

const result = await generateText({ model, tools, prompt });
const events = fromVercelAI(result, { session: crypto.randomUUID(), prompt, end: true });
await deliver(events, { repo: ".tine-repo" }); // runs `tine hook capture` per event
```

```ts
import { run } from "@openai/agents";
import { fromOpenAIAgents, deliver } from "@opentine/capture";

const result = await run(agent, input);
await deliver(fromOpenAIAgents(result, { session: id, prompt: input }), { repo: ".tine-repo" });
```

What is recorded: the prompt (when you pass it), one `tool` step per tool
call in order with its result paired by call id (a Vercel `tool-error` is
recorded as `{error}`; Agents handoffs are tool calls), then `turn_end` with
the final text (`text` / `finalOutput`), and `session_end` when `end: true`.
One `session` is one run on `heads/capture/<agent>/...`; call the adapter once
per turn with the same session to grow the run.

`deliver` spawns `tine hook capture --agent=generic --repo=PATH` once per
event without a shell (`command` overrides `["tine"]`, e.g.
`["uvx", "--from", "opentine", "tine"]`) and stops at the first `ok: false`.
Capture must be enabled in the repository (`tine enable`). `toJsonl` writes
the events as JSON Lines instead.

Events are checked as the receiver will check them: the session must be a
non-empty string (cut to 512 code points), tool names are cut to 256, and an
event over 8 MiB is refused before it is sent.

The fixtures in `test/fixtures` are hand-written to the documented result
shapes; `tests/test_047_capture_sdk.py` feeds the expected events to the
Python recorder, so the producer and the receiver are held to one file.

```
npm ci && npm test && npm audit --audit-level=low
```
