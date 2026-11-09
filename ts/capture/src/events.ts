// opentine-hook/1 events (docs/spec/hook-1.md): the generic envelope that
// `tine hook capture` reads on stdin. Every adapter in this package produces
// these and nothing else, so what reaches the recorder is the documented
// protocol, never a vendor object.

export const PROTOCOL = "opentine-hook/1" as const;
/** The receiver refuses a payload larger than this (hook-1 §1). */
export const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;
const MAX_SESSION = 512;
const MAX_TOOL_NAME = 256;

export type EventName = "prompt" | "tool" | "turn_end" | "session_end";

export interface ToolCall {
  name: string;
  input?: unknown;
  output?: unknown;
}

export interface HookEvent {
  protocol: typeof PROTOCOL;
  event: EventName;
  session: string;
  prompt?: unknown;
  message?: unknown;
  cwd?: string;
  tool?: ToolCall;
}

export interface CaptureOptions {
  /** The session id; one session is one run in the repository (hook-1 §5). */
  session: string;
  /** The user prompt to record first, when the caller has it. */
  prompt?: unknown;
  /** The working directory to record on each event. */
  cwd?: string;
  /** Also emit `session_end`, which marks the run completed. Default false. */
  end?: boolean;
}

export class CaptureError extends Error {}

function codePoints(text: string, limit: number): string {
  const points = Array.from(text);
  return points.length > limit ? points.slice(0, limit).join("") : text;
}

/** Normalise the session the same way the receiver will (hook-1 §2.3). */
export function checkSession(session: unknown): string {
  if (typeof session !== "string" || session.length === 0) {
    throw new CaptureError("session must be a non-empty string");
  }
  return codePoints(session, MAX_SESSION);
}

/** Build one event; omits fields that are undefined so the JSON stays minimal. */
export function event(
  name: EventName,
  options: CaptureOptions,
  fields: { prompt?: unknown; message?: unknown; tool?: ToolCall } = {},
): HookEvent {
  const out: HookEvent = { protocol: PROTOCOL, event: name, session: checkSession(options.session) };
  if (fields.prompt !== undefined) out.prompt = fields.prompt;
  if (fields.message !== undefined) out.message = fields.message;
  if (fields.tool !== undefined) {
    const tool: ToolCall = { name: codePoints(String(fields.tool.name ?? ""), MAX_TOOL_NAME) };
    if (fields.tool.input !== undefined) tool.input = fields.tool.input;
    if (fields.tool.output !== undefined) tool.output = fields.tool.output;
    out.tool = tool;
  }
  if (typeof options.cwd === "string") out.cwd = options.cwd;
  return out;
}

/** The bytes sent on stdin: one JSON object, refused when over the receiver's bound. */
export function serialize(value: HookEvent): string {
  const text = JSON.stringify(value);
  if (text === undefined) throw new CaptureError("event is not JSON-serializable");
  if (Buffer.byteLength(text, "utf8") > MAX_PAYLOAD_BYTES) {
    throw new CaptureError(`event exceeds ${MAX_PAYLOAD_BYTES} bytes`);
  }
  return text;
}

/** Leading prompt and trailing turn_end / session_end around tool events. */
export function frame(
  options: CaptureOptions,
  tools: ToolCall[],
  message: unknown,
): HookEvent[] {
  const out: HookEvent[] = [];
  if (options.prompt !== undefined) out.push(event("prompt", options, { prompt: options.prompt }));
  for (const tool of tools) out.push(event("tool", options, { tool }));
  out.push(event("turn_end", options, message === undefined ? {} : { message }));
  if (options.end) out.push(event("session_end", options));
  return out;
}
