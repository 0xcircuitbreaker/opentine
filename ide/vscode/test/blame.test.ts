import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { aiShare, gutterRows, parseBlame, shortRun } from "../src/blame.js";

const FIXTURE = path.join(__dirname, "..", "..", "test", "fixtures", "blame-lines.json");

function record() {
  return parseBlame(JSON.parse(readFileSync(FIXTURE, "utf-8")));
}

test("only AI-written lines get a gutter row, 0-based", () => {
  const rows = gutterRows(record());
  assert.deepEqual(rows.map((row) => row.index), [1, 2]);
  assert.equal(rows[0].label, "AI claude-sonnet-4-5 be292c795e4d");
  assert.match(rows[0].hover, /step 4/);
  assert.doesNotMatch(rows[1].hover, /step/);
});

test("the AI share is the record's own count", () => {
  assert.equal(aiShare(record()), "2 of 3 lines AI-written (67%)");
});

test("a record of the other tine-blame/1 shape or another schema is refused", () => {
  assert.throws(() => parseBlame({ schema: "tine-blame/1", hits: [] }), /tine blame --lines --json/);
  assert.throws(() => parseBlame({ schema: "tine-blame/2", lines: [] }), /tine-blame\/1/);
});

test("a run id shortens to its digest, never to its prefix", () => {
  assert.equal(shortRun("run:sha256:" + "ab".repeat(32)), "abababababab");
  assert.equal(shortRun("legacy_run"), "legacy_run");
});
