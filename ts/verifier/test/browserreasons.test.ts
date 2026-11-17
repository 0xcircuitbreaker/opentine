/** 0.53: the browser verifier refuses a wrapped file with the CLI's reason text and code. */

import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateSync } from "node:zlib";
import { verifyArtifact } from "../src/browser/entry.js";
import { MAGIC } from "../src/codec.js";
import { verifyBytes } from "../src/verify.js";

function uvarint(value: number): number[] {
  const out: number[] = [];
  while (value >= 0x80) {
    out.push((value & 0x7f) | 0x80);
    value = Math.floor(value / 128);
  }
  out.push(value);
  return out;
}

function wrapped(codec: number, size: number, frame: Uint8Array): Uint8Array {
  return new Uint8Array([...MAGIC, codec, ...uvarint(size), ...frame]);
}

const body = new TextEncoder().encode('{"format_version":4}');
const cases: Array<[string, Uint8Array]> = [
  ["truncated header", new Uint8Array([...MAGIC, 1, 0x80])],
  ["oversized", wrapped(1, 2 ** 30, deflateSync(body))],
  ["ratio", wrapped(1, 200_000, new Uint8Array([1]))],
  ["corrupt frame", wrapped(1, body.length, new Uint8Array([1, 2, 3, 4]))],
  ["overlong output", wrapped(1, body.length - 1, deflateSync(body))],
  ["short output", wrapped(1, body.length + 1, deflateSync(body))],
  ["nested", wrapped(1, MAGIC.length + 2, deflateSync(new Uint8Array([...MAGIC, 0, 0])))],
];

for (const [name, raw] of cases) {
  test(`browser and CLI refuse a ${name} wrapper alike`, async () => {
    const cli = verifyBytes(raw, "artifact");
    const browser = await verifyArtifact(raw, "artifact");
    assert.equal(cli.ok, false);
    assert.ok(cli.integrity.code?.startsWith("codec."), cli.integrity.reason);
    assert.deepEqual(browser.integrity, cli.integrity);
  });
}
