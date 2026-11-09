// Delivering events to `tine hook capture` (hook-1 §1): one process per event,
// the event on stdin, one JSON response on stdout, exit status always 0.
// Spawned without a shell, so no argument is ever re-parsed.

import { spawn } from "node:child_process";
import { CaptureError, type HookEvent, serialize } from "./events.js";

export interface HookResponse {
  protocol?: string;
  ok?: boolean;
  event?: string;
  ref?: string;
  run?: string;
  steps?: number;
  reason?: string;
  steer?: string[];
}

export interface SinkOptions {
  /** The run repository (`--repo`). */
  repo: string;
  /** The `--agent` name; the run lands on heads/capture/<agent>/... Default "generic". */
  agent?: string;
  /** The command to run; default ["tine"]. E.g. ["uvx", "--from", "opentine", "tine"]. */
  command?: string[];
  /** Milliseconds before one delivery is abandoned. Default 30000. */
  timeoutMs?: number;
}

const AGENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/;
const MAX_RESPONSE = 1024 * 1024;

function runOnce(argv: string[], input: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), { shell: false, stdio: ["pipe", "pipe", "ignore"] });
    const chunks: Buffer[] = [];
    let size = 0;
    const timer = setTimeout(() => {
      child.kill();
      reject(new CaptureError(`tine hook capture did not answer in ${timeoutMs} ms`));
    }, timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size <= MAX_RESPONSE) chunks.push(chunk);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(new CaptureError(`cannot run ${argv[0]}: ${error.message}`));
    });
    child.on("close", () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    child.stdin.on("error", () => undefined); // a receiver that exits early is answered by stdout
    child.stdin.end(input);
  });
}

/** Send *events* in order; resolves with each response. Stops at the first `ok: false`. */
export async function deliver(events: HookEvent[], options: SinkOptions): Promise<HookResponse[]> {
  const agent = options.agent ?? "generic";
  if (!AGENT.test(agent)) throw new CaptureError(`agent name ${JSON.stringify(agent)} is not plain`);
  const command = options.command ?? ["tine"];
  if (command.length === 0) throw new CaptureError("command must name a program");
  const argv = [...command, "hook", "capture", `--agent=${agent}`, `--repo=${options.repo}`];
  const responses: HookResponse[] = [];
  for (const item of events) {
    const text = await runOnce(argv, serialize(item), options.timeoutMs ?? 30_000);
    let response: HookResponse;
    try {
      response = JSON.parse(text.trim().split("\n").pop() ?? "") as HookResponse;
    } catch {
      throw new CaptureError(`tine hook capture answered something that is not JSON`);
    }
    responses.push(response);
    if (response.ok === false) break; // a vendor --agent is answered {} (hook-1 §6)
  }
  return responses;
}

/** Events as JSON Lines, e.g. to replay later with `tine hook capture < line`. */
export function toJsonl(events: HookEvent[]): string {
  return events.map((item) => `${serialize(item)}\n`).join("");
}
