/**
 * Running `tine`: an argument list, never a shell string, in the workspace
 * folder, with a timeout. A path handed to `tine` is repository-relative and
 * POSIX (`/`), whatever the platform, so `tine blame` and `tine why` see the
 * same name git does.
 */

import { execFile } from "node:child_process";
import * as path from "node:path";

export interface TineResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** `command` is the executable and any fixed leading arguments (e.g. `["tine"]`). */
export function runTine(command: string[], args: string[], cwd: string, timeoutMs = 60_000): Promise<TineResult> {
  if (command.length === 0) return Promise.reject(new Error("no tine executable configured"));
  const [file, ...lead] = command;
  return new Promise((resolve, reject) => {
    execFile(
      file,
      [...lead, ...args],
      { cwd, timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024, windowsHide: true, shell: false },
      (error, stdout, stderr) => {
        if (error && typeof (error as NodeJS.ErrnoException).code === "string") {
          reject(new Error(`cannot run ${file}: ${error.message}`));
          return;
        }
        const code = error ? (typeof error.code === "number" ? error.code : 1) : 0;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      },
    );
  });
}

/** The JSON document a `--json` call printed, or an Error naming what went wrong. */
export function parseJson(result: TineResult): Record<string, unknown> {
  const text = result.stdout.trim();
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(result.stderr.trim() || `tine printed no JSON (exit ${result.code})`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("tine printed a JSON value that is not an object");
  const error = (value as Record<string, unknown>).error;
  if (error && typeof error === "object") {
    const message = (error as Record<string, unknown>).message;
    throw new Error(typeof message === "string" ? message : `tine failed (exit ${result.code})`);
  }
  return value as Record<string, unknown>;
}

/** *file* relative to *root*, with `/` separators; refuses a file outside *root*. */
export function repoRelative(root: string, file: string, sep: string = path.sep): string {
  const rel = (sep === "\\" ? path.win32 : path.posix).relative(root, file);
  if (rel === "" || rel.startsWith("..") || (sep === "\\" ? path.win32 : path.posix).isAbsolute(rel)) {
    throw new Error(`${file} is not inside ${root}`);
  }
  return rel.split(sep).join("/");
}
