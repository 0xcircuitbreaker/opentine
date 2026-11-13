#!/usr/bin/env node
/**
 * opentine-verify FILE [--pubkey HEX|FILE] [--hmac-key-file FILE] [--trust-embedded]
 *
 * FILE is a `.tine` artifact, (0.45) a `verdicts.jsonl` of `tine-eval-verdict/1`
 * objects, checked under --pubkey or, without it, each verdict's embedded key,
 * or (0.51) a `tine bundle` file (`TINEBUNDLE1`), streamed from disk.
 * `--version` prints the OpenTine release this build was made for.
 *
 * Prints one JSON report. Exit 0: intact, and no signature check failed (an
 * unsigned or unchecked file still passes integrity; read `signature.state`).
 * Exit 1: integrity or signature failure. Exit 2: usage error.
 */

import { existsSync, readFileSync } from "node:fs";
import { isBundle, verifyBundle } from "./bundle.js";
import { fileSource } from "./filesource.js";
import { OPENTINE_VERSION } from "./version.js";
import { TineError } from "./errors.js";
import type { VerifyKeys } from "./signature.js";
import { verifyFile } from "./verify.js";
import { verifyEvalFile } from "./evalverdict.js";

const USAGE =
  "usage: opentine-verify FILE [--pubkey HEX|FILE] [--hmac-key-file FILE] [--trust-embedded]\n" +
  "  Verifies a .tine format v4 artifact: every envelope id, the root, the\n" +
  "  annotation chain and its tine-sig/3 signatures. Exactly one key option.\n" +
  "  A FILE ending in .jsonl is a tine eval verdicts.jsonl (Ed25519 verdicts).\n" +
  "  A tine bundle file (TINEBUNDLE1) is verified as `tine bundle verify` does.\n";

function keyMaterial(text: string): Uint8Array {
  const raw = existsSync(text) ? readFileSync(text) : Buffer.from(text, "utf8");
  const trimmed = raw.toString("latin1").trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return Uint8Array.from(Buffer.from(trimmed, "hex"));
  if (raw.length === 32) return Uint8Array.from(raw);
  throw new TineError("--pubkey must be a raw 32-byte key or 64 hex characters");
}

/** The raw key bytes, minus one trailing newline an editor may have added. */
function hmacKeyFile(path: string): Uint8Array {
  const raw = readFileSync(path);
  return Uint8Array.from(raw.at(-1) === 0x0a ? raw.subarray(0, -1) : raw);
}

async function main(argv: string[]): Promise<number> {
  const keys: VerifyKeys = {};
  let file: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "-h" || arg === "--help") {
      process.stdout.write(USAGE);
      return 0;
    }
    if (arg === "--version") {
      process.stdout.write(`${OPENTINE_VERSION}\n`);
      return 0;
    }
    if (arg === "--pubkey") keys.publicKey = keyMaterial(argv[++i] ?? "");
    else if (arg === "--hmac-key-file") keys.hmacKey = hmacKeyFile(argv[++i] ?? "");
    else if (arg === "--trust-embedded") keys.trustEmbedded = true;
    else if (arg.startsWith("-") || file !== undefined) {
      process.stderr.write(USAGE);
      return 2;
    } else file = arg;
  }
  if (file === undefined) {
    process.stderr.write(USAGE);
    return 2;
  }
  if (file.endsWith(".jsonl")) {
    // 0.45: a verdicts.jsonl of tine-eval-verdict/1 objects (Ed25519 only).
    const evalReport = verifyEvalFile(file, keys.publicKey ?? undefined);
    process.stdout.write(JSON.stringify(evalReport, null, 2) + "\n");
    return evalReport.ok ? 0 : 1;
  }
  const source = fileSource(file);
  try {
    if (isBundle(await source.read(0, 12))) {
      const bundle = await verifyBundle(source);
      process.stdout.write(JSON.stringify(bundle, null, 2) + "\n");
      return bundle.ok ? 0 : 1;
    }
  } finally {
    source.close();
  }
  const report = verifyFile(file, keys);
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  return report.ok ? 0 : 1;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (exc) => {
    process.stderr.write(`opentine-verify: ${(exc as Error).message}\n`);
    process.exitCode = 2;
  },
);
