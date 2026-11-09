# `opentine-hook/1` — the per-turn agent hook protocol

**Version:** 1 (protocol tag `opentine-hook/1`). **Status:** normative from
opentine 0.46.0; the protocol itself has shipped unchanged since 0.38 (capture),
0.43 (steer) and 0.45.1 (vendor dialects), and this document only writes it
down. **Conformance:** `docs/conformance/vectors/67-hook.json` (ops
`hook.normalize` and `hook.respond`), answered by the Python reference, the TS
verifier (`ts/verifier/src/hook.ts`) and `tine-verify.pyz`
(`opentine/_pyz/_hook.py`). **Schema:**
[`opentine-hook-1`](../schemas/opentine-hook-1.schema.json). **SPEC:**
[§8.16](../SPEC.md#s-8.16).

A change that makes a conforming implementation answer any vector differently
is a new protocol version (`opentine-hook/2`), never an edit of this one. New
vendor dialects (§4) may be added within version 1 when they only *add*
payloads that version 1 refused.

## 1. Transport

An agent CLI runs one command per hook event:

    tine hook capture --agent NAME [--event VENDOR_EVENT] --repo PATH

One JSON object arrives on **stdin** (at most 8 MiB). One JSON object leaves
on **stdout**, followed by a newline. The exit status is **always 0**: a hook
must never break the agent, so every failure is an `ok: false` response, never
a non-zero exit. Capture is off unless the repository's *trusted* porcelain
config sets `hooks.capture` (`tine enable` does).

## 2. The event envelope

The generic form, for any harness that can run a command:

```json
{"protocol": "opentine-hook/1", "event": "prompt|tool|turn_end|session_end",
 "session": "<id>", "prompt": "...", "tool": {"name": "...", "input": ..., "output": ...},
 "message": "...", "cwd": "..."}
```

A receiver reads a payload into the event `{event, session, prompt, tool:
{name, input, output}, message, cwd}` with these rules, in this order (values
are JSON; "truthy" is Python truthiness: `null`, `false`, `0`, `""`, `[]` and
`{}` are falsy):

1. Apply the vendor translation of §4. A payload that is not a JSON object is
   **refused**.
2. **event.** If `protocol` is exactly `opentine-hook/1`, take `event`. If that
   is not truthy, map `hook_event_name` through the table of §3. The result
   must be one of `prompt`, `tool`, `turn_end`, `session_end`, else the payload
   is **refused**.
3. **session.** `session` if truthy, else `session_id`. It must be a non-empty
   string, else **refused**. It is cut to its first 512 code points.
4. **tool.** `tool` when it is an object, else `{}`. `name` is `tool.name` if
   it is a non-empty string, else `tool_name` if that is one, else `""`; cut to
   256 code points. `input` is `tool.input` when present, else `tool_input`;
   `output` is `tool.output` when present, else `tool_response`.
5. **message** is `message` when present, else `last_assistant_message`;
   **prompt** is `prompt`; **cwd** is `cwd` when a string, else `""`.

A refused payload is answered `{"protocol": "opentine-hook/1", "ok": false,
"reason": "..."}`; the `reason` text is informative only.

## 3. Vendor event names

| `hook_event_name` | event | sent by |
|---|---|---|
| `UserPromptSubmit` | `prompt` | Claude Code, Codex, Copilot CLI, Droid |
| `BeforeAgent` | `prompt` | Gemini CLI |
| `PreInvocation` | `prompt` | Antigravity (via `--event`) |
| `PostToolUse` | `tool` | Claude Code, Codex, Copilot CLI, Droid, Antigravity |
| `AfterTool` | `tool` | Gemini CLI |
| `Stop` | `turn_end` | Claude Code, Codex, Copilot CLI, Droid, Antigravity |
| `AfterAgent` | `turn_end` | Gemini CLI |
| `SessionEnd` | `session_end` | Claude Code, Codex, Gemini CLI, Copilot CLI, Droid |

Every other name (`PreToolUse`, `SessionStart`, ...) is refused: it is not a
capture event.

## 4. Vendor translation

Applied before §2, to an object payload, with `hint` the `--event` value:

* **Antigravity** — when `hint` is given, the payload has no `hook_event_name`
  and has `conversationId`: it is replaced by `{hook_event_name: hint,
  session_id: conversationId}`, plus `cwd` = `workspacePaths[0]` when that is a
  string; for `PreInvocation`, `prompt` = `lastUserInput`; for `PostToolUse`,
  `tool_name` = `toolCall.name`, `tool_input` = `toolCall.args`, and
  `tool_response` = `{"error": error}` when `error` is not null.
* **Any other payload without its event name** — when `hint` is given and the
  payload has neither `hook_event_name` nor `protocol`, `hook_event_name` is
  set to `hint`. A named event is never overridden by the hint.
* **Gemini CLI** — `prompt_response` is read as `last_assistant_message` when
  the latter is absent.
* **Copilot CLI** — `tool_result` is read as `tool_response` when the latter is
  absent; a `{result_type, text_result_for_llm}` result becomes `{type, text}`.

## 5. Recording

Each session is one run on `heads/capture/<agent>/<first 32 hex of
SHA-256(session)>`, where `<agent>` is the `--agent` value lowercased with
every character outside `[a-z0-9-]` replaced by `-` (at most 40, else
`generic`). Each accepted event is one step, durable before the command
returns. `session_end` marks the run `completed`. The step attributes carry
`opentine.hook.protocol`, `opentine.hook.event` and `opentine.hook.agent`.

## 6. The response

The generic response (`--agent generic`) is

```json
{"protocol": "opentine-hook/1", "ok": true, "event": "turn_end", "ref": "...",
 "run": "...", "steps": 3, "steer": ["..."]}
```

`steer` is present only when messages were delivered at this turn end
(`tine fleet send`; each is also recorded as a `human` step with actor
`steer`). A vendor CLI parses stdout as its own control JSON, so it is
answered instead with only the decision its turn-end hook documents for
"continue, with this as the next prompt" (`hook.respond`):

| agent | steer delivered | none |
|---|---|---|
| `claude-code` | `{"decision": "block", "reason": TEXT}` | `{"suppressOutput": true}` |
| `codex` | `{"decision": "block", "reason": TEXT}` | `{}` |
| `gemini` | `{"decision": "deny", "reason": TEXT}` | `{}` |
| any other | `{}` (the steer is recorded, not injected) | `{}` |

`TEXT` is the messages joined by `"\n\n"`. Messages are taken from the mailbox
once, so a re-entered turn end (`stop_hook_active: true`) never loops.

## 7. Resume

`tine hook resume --agent codex|gemini|claude-code --session ID --message TEXT
[--repo PATH] [--dry-run]` continues an *ended* session with the CLI's own
resume command, run without a shell: `codex exec resume ID TEXT`, `gemini
--resume ID --prompt TEXT`, `claude --resume ID --print TEXT`. With `--repo`
the message is first recorded as a `steer` step (`opentine.steer.from:
"resume"`) on the session's capture run when it exists. A session id must match
`[A-Za-z0-9][A-Za-z0-9._:-]{0,255}` and a message must not start with `-`, so
neither can be read as an option. `--dry-run` prints the plan
(`tine-cli-hook-resume-1`). The program is resolved on `PATH`; where it is a
Windows `.cmd`/`.bat` shim (run by cmd.exe, which re-parses arguments) a
message carrying `" % ^ & | < > ! ( )` or a line break is refused.

## Sources

* Codex hooks: https://learn.chatgpt.com/docs/hooks (`Stop`: `decision:
  "block"` + `reason` continues the turn as a new user prompt).
* Gemini CLI hooks: https://geminicli.com/docs/hooks/reference (`AfterAgent`:
  `decision: "deny"` + `reason` sends the reason as a new prompt).
* Claude Code hooks: https://docs.claude.com/en/docs/claude-code/hooks.
