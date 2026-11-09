import { test } from "node:test";
import assert from "node:assert/strict";
import { CaptureError, MAX_PAYLOAD_BYTES, event, serialize } from "../src/index.js";

test("the session is required and cut to 512 code points like the receiver does", () => {
  assert.throws(() => event("prompt", { session: "" }), CaptureError);
  assert.throws(() => event("prompt", { session: 5 as unknown as string }), CaptureError);
  const long = "😀".repeat(600);
  assert.equal(Array.from(event("turn_end", { session: long }).session).length, 512);
});

test("tool names are cut to 256 code points and undefined fields are omitted", () => {
  const out = event("tool", { session: "s" }, { tool: { name: "n".repeat(300), input: undefined } });
  assert.deepEqual(Object.keys(out.tool ?? {}), ["name"]);
  assert.equal(out.tool?.name.length, 256);
});

test("serialize refuses what the receiver would refuse for size", () => {
  const big = event("prompt", { session: "s" }, { prompt: "x".repeat(MAX_PAYLOAD_BYTES) });
  assert.throws(() => serialize(big), /exceeds/);
  assert.equal(serialize(event("turn_end", { session: "s" })),
    '{"protocol":"opentine-hook/1","event":"turn_end","session":"s"}');
});
