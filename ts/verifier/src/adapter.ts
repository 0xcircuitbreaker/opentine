#!/usr/bin/env node
/**
 * The PROTOCOL.md adapter, so the neutral harness can score this package too:
 *
 *   python docs/conformance/run_conformance.py --level 2 \
 *     --adapter "node ts/verifier/dist/src/adapter.js" \
 *     --capability ed25519 --capability wtf8 --capability zlib
 */

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { TineError } from "./errors.js";
import { decodeTagged, runOp, Unsupported, type KeyTable, type OpInput } from "./ops.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const table: KeyTable = {};
for (const [name, text] of Object.entries(
  JSON.parse(readFileSync(join(root, "docs", "conformance", "keys.json"), "utf8")) as Record<string, string>,
)) {
  table[name] = Uint8Array.from(Buffer.from(text, "hex"));
}

function input(spec: Record<string, unknown>): OpInput {
  if ("value" in spec) return { value: decodeTagged(spec.value) };
  return { bytes: Uint8Array.from(Buffer.from(spec.bytes_b64 as string, "base64")) };
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  if (!line.trim()) continue;
  const request = JSON.parse(line) as { id: string; op: string; input: Record<string, unknown>; args?: Record<string, unknown> };
  let response: Record<string, unknown>;
  try {
    response = { id: request.id, ok: true, output: runOp(request.op, input(request.input), request.args ?? {}, table) };
  } catch (exc) {
    if (exc instanceof Unsupported) response = { id: request.id, ok: false, unsupported: true };
    else {
      const reason = exc instanceof TineError ? exc.code : "";
      response = { id: request.id, ok: false, reason, message: String((exc as Error).message).slice(0, 200) };
    }
  }
  process.stdout.write(JSON.stringify(response) + "\n");
}
