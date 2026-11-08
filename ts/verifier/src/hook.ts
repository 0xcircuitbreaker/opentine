/**
 * SPEC 8.16 / docs/spec/hook-1.md (0.46): the `opentine-hook/1` event envelope.
 * A port of `opentine/_hook_protocol.py` `normalize` (with the vendor
 * translations of `_hook_dialects.py`) and of `_hook_mailbox.py`
 * `vendor_response`. Truthiness is Python's (`truthy`), and lengths are code
 * points, so every implementation cuts a session id at the same place.
 */

import { isObject, truthy, type JObject, type JValue } from "./json.js";

const PROTOCOL = "opentine-hook/1";
const KINDS = new Set(["prompt", "tool", "turn_end", "session_end"]);
const EVENTS: Record<string, string> = {
  UserPromptSubmit: "prompt",
  BeforeAgent: "prompt",
  PreInvocation: "prompt",
  PostToolUse: "tool",
  AfterTool: "tool",
  Stop: "turn_end",
  AfterAgent: "turn_end",
  SessionEnd: "session_end",
};
const CONTINUE: Record<string, string> = { "claude-code": "block", codex: "block", gemini: "deny" };

function cut(text: string, limit: number): string {
  const points = Array.from(text);
  return points.length > limit ? points.slice(0, limit).join("") : text;
}

function antigravity(payload: JObject, event: string): JObject {
  const call = payload.get("toolCall");
  const out: JObject = new Map<string, JValue>([
    ["hook_event_name", event],
    ["session_id", payload.get("conversationId") ?? null],
  ]);
  const paths = payload.get("workspacePaths");
  if (Array.isArray(paths) && paths.length > 0 && typeof paths[0] === "string") out.set("cwd", paths[0]);
  if (event === "PreInvocation") out.set("prompt", payload.get("lastUserInput") ?? null);
  else if (event === "PostToolUse") {
    out.set("tool_name", isObject(call) ? (call.get("name") ?? null) : null);
  }
  return out;
}

function translate(payload: JObject, hint: string | null): JObject {
  if (hint && !payload.has("hook_event_name") && payload.has("conversationId")) {
    return antigravity(payload, hint);
  }
  let out = payload;
  if (hint && !out.has("hook_event_name") && !out.has("protocol")) {
    out = new Map(out);
    out.set("hook_event_name", hint);
  }
  return out;
}

function name(value: JValue | undefined): string {
  return typeof value === "string" ? cut(value, 256) : "";
}

export function hookNormalize(value: JValue): Record<string, unknown> {
  const refused = { ok: false, event: null, session: null, tool_name: null, cwd: null };
  if (!isObject(value)) return refused;
  const raw = value.get("payload");
  const hint = value.get("hint");
  if (!isObject(raw)) return refused;
  const payload = translate(raw, typeof hint === "string" ? hint : null);
  let kind: JValue | undefined = payload.get("protocol") === PROTOCOL ? payload.get("event") : null;
  const vendor = payload.get("hook_event_name");
  if (!truthy(kind)) kind = typeof vendor === "string" && Object.hasOwn(EVENTS, vendor) ? EVENTS[vendor] : null;
  const first = payload.get("session");
  const session = truthy(first) ? first : payload.get("session_id");
  if (typeof kind !== "string" || !KINDS.has(kind) || typeof session !== "string" || session === "") {
    return refused;
  }
  const tool = payload.get("tool");
  const cwd = payload.get("cwd");
  return {
    ok: true,
    event: kind,
    session: cut(session, 512),
    tool_name: (isObject(tool) ? name(tool.get("name")) : "") || name(payload.get("tool_name")),
    cwd: typeof cwd === "string" ? cwd : "",
  };
}

export function hookRespond(value: JValue): Record<string, unknown> {
  if (!isObject(value)) throw new Error("hook.respond takes an object");
  const agent = value.get("agent");
  const steer = value.get("steer");
  const messages = Array.isArray(steer) ? steer.filter((item): item is string => typeof item === "string") : [];
  if (typeof agent === "string" && messages.length > 0 && Object.hasOwn(CONTINUE, agent)) {
    return { stdout: { decision: CONTINUE[agent], reason: messages.join("\n\n") } };
  }
  return { stdout: agent === "claude-code" ? { suppressOutput: true } : {} };
}
