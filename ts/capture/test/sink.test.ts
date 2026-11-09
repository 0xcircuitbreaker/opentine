import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { CaptureError, deliver, event, toJsonl } from "../src/index.js";

const FAKE = fileURLToPath(new URL("../../test/fixtures/fake-tine.mjs", import.meta.url));
const command = [process.execPath, FAKE];

test("deliver runs one receiver per event, in order, with --agent and --repo bound", async () => {
  const events = [event("prompt", { session: "s" }, { prompt: "p" }), event("turn_end", { session: "s" })];
  const answers = await deliver(events, { repo: "-odd repo", command });
  assert.deepEqual(answers.map((a) => a.event), ["prompt", "turn_end"]);
  assert.deepEqual((answers[0] as any).argv, ["hook", "capture", "--agent=generic", "--repo=-odd repo"]);
});

test("deliver stops at the first refusal", async () => {
  const events = [event("prompt", { session: "refuse-me" }), event("turn_end", { session: "refuse-me" })];
  const answers = await deliver(events, { repo: "r", command });
  assert.equal(answers.length, 1);
  assert.equal(answers[0].ok, false);
});

test("deliver refuses an agent name that is not plain and a missing program", async () => {
  await assert.rejects(deliver([], { repo: "r", agent: "--evil", command }), CaptureError);
  await assert.rejects(
    deliver([event("prompt", { session: "s" })], { repo: "r", command: ["/no/such/tine-binary"] }),
    CaptureError,
  );
});

test("toJsonl writes one event per line", () => {
  const text = toJsonl([event("prompt", { session: "s" }), event("turn_end", { session: "s" })]);
  assert.equal(text.split("\n").length, 3);
  assert.equal(JSON.parse(text.split("\n")[1]).event, "turn_end");
});
