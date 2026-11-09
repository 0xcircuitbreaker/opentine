// Adapters from SDK result objects to opentine-hook/1 events.
//
// Both read the *result* an SDK returns after a run (structurally typed, so
// this package depends on neither SDK): the tool calls in order, each paired
// with its result by call id, then the final text as the turn_end message.

import { type CaptureOptions, type HookEvent, type ToolCall, frame } from "./events.js";

type Obj = Record<string, unknown>;

function isObj(value: unknown): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function parsedArguments(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return value; // a model may emit arguments that are not JSON; keep the text
  }
}

/** Calls in order, results attached by id; a call with no result keeps only its input. */
function pair(calls: Array<[string, ToolCall]>, results: Map<string, unknown>): ToolCall[] {
  return calls.map(([id, call]) => (results.has(id) ? { ...call, output: results.get(id) } : call));
}

// --------------------------------------------------------------------------
// Vercel AI SDK (`ai`): generateText / streamText results, v4 and v5 shapes.
// --------------------------------------------------------------------------

/** The tool calls of a `generateText` (or awaited `streamText`) result. */
export function vercelToolCalls(result: unknown): ToolCall[] {
  const steps = isObj(result) && Array.isArray(result.steps) ? result.steps : [result];
  const calls: Array<[string, ToolCall]> = [];
  const results = new Map<string, unknown>();
  for (const step of steps) {
    if (!isObj(step)) continue;
    for (const call of list(step.toolCalls)) {
      if (!isObj(call)) continue;
      const input = "input" in call ? call.input : call.args; // v5 input, v4 args
      calls.push([String(call.toolCallId ?? ""), { name: String(call.toolName ?? ""), input }]);
    }
    for (const done of list(step.toolResults)) {
      if (!isObj(done)) continue;
      results.set(String(done.toolCallId ?? ""), "output" in done ? done.output : done.result);
    }
    for (const part of list(step.content)) {
      if (isObj(part) && part.type === "tool-error") {
        results.set(String(part.toolCallId ?? ""), { error: String(part.error ?? "") });
      }
    }
  }
  return pair(calls, results);
}

/** Events for one Vercel AI SDK run: prompt, one `tool` per call, `turn_end` with `text`. */
export function fromVercelAI(result: unknown, options: CaptureOptions): HookEvent[] {
  const text = isObj(result) && typeof result.text === "string" ? result.text : undefined;
  return frame(options, vercelToolCalls(result), text);
}

// --------------------------------------------------------------------------
// OpenAI Agents SDK (`@openai/agents`): a RunResult's `newItems`.
// --------------------------------------------------------------------------

const CALL_ITEMS = new Set(["tool_call_item", "handoff_call_item"]);
const OUTPUT_ITEMS = new Set(["tool_call_output_item", "handoff_output_item"]);

function raw(item: Obj): Obj {
  return isObj(item.rawItem) ? item.rawItem : item;
}

/** The tool (and handoff) calls of an Agents SDK `RunResult`. */
export function agentsToolCalls(result: unknown): ToolCall[] {
  const items = isObj(result) ? list(result.newItems) : list(result);
  const calls: Array<[string, ToolCall]> = [];
  const results = new Map<string, unknown>();
  for (const item of items) {
    if (!isObj(item) || typeof item.type !== "string") continue;
    const body = raw(item);
    const id = String(body.callId ?? body.id ?? "");
    if (CALL_ITEMS.has(item.type)) {
      const name = String(body.name ?? body.type ?? "");
      calls.push([id, { name, input: parsedArguments(body.arguments ?? body.input) }]);
    } else if (OUTPUT_ITEMS.has(item.type)) {
      results.set(id, "output" in item ? item.output : body.output);
    }
  }
  return pair(calls, results);
}

/** Events for one Agents SDK run: prompt, one `tool` per call, `turn_end` with `finalOutput`. */
export function fromOpenAIAgents(result: unknown, options: CaptureOptions): HookEvent[] {
  const final = isObj(result) ? result.finalOutput : undefined;
  return frame(options, agentsToolCalls(result), final === null ? undefined : final);
}
