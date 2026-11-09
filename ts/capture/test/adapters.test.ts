import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fromOpenAIAgents, fromVercelAI, type CaptureOptions } from "../src/index.js";

const FIXTURES = new URL("../../test/fixtures/", import.meta.url);
const read = (name: string): any => JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8"));
const ADAPTERS: Record<string, (result: unknown, options: CaptureOptions) => unknown> = {
  fromVercelAI,
  fromOpenAIAgents,
};

for (const item of read("expected.json").cases) {
  test(`${item.adapter} turns ${item.fixture} into the expected events`, () => {
    const events = ADAPTERS[item.adapter](read(item.fixture), item.options);
    assert.deepEqual(events, item.events);
  });
}

test("a vercel result without steps is read as one step", () => {
  const events = fromVercelAI(
    { text: "hi", toolCalls: [{ toolCallId: "x", toolName: "t", input: 1 }], toolResults: [] },
    { session: "s" },
  );
  assert.deepEqual(events, [
    { protocol: "opentine-hook/1", event: "tool", session: "s", tool: { name: "t", input: 1 } },
    { protocol: "opentine-hook/1", event: "turn_end", session: "s", message: "hi" },
  ]);
});

test("garbage results produce only a turn_end, never a throw", () => {
  for (const junk of [null, 7, "x", [], { steps: [null, 3, { toolCalls: [null] }] }, { newItems: [1, {}] }]) {
    assert.equal((fromVercelAI(junk, { session: "s" }) as unknown[]).length, 1);
    assert.equal((fromOpenAIAgents(junk, { session: "s" }) as unknown[]).length, 1);
  }
});

test("an agents run with a structured finalOutput keeps it as the message", () => {
  const [end] = fromOpenAIAgents({ newItems: [], finalOutput: { answer: 42 } }, { session: "s" });
  assert.deepEqual(end.message, { answer: 42 });
});
