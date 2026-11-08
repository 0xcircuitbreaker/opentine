/** The web trailer parser gives the same link set as `tine git log` on every vector. */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { parseTrailers, TrailerError } from "../src/trailers.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const vectors = JSON.parse(readFileSync(join(ROOT, "tests", "data", "trailer_vectors.json"), "utf-8")) as {
  cases: Array<{ name: string; message: string; links?: unknown; error?: string }>;
};

test("trailer vectors are present", () => {
  assert.ok(vectors.cases.length >= 13);
});

for (const vector of vectors.cases) {
  test(`trailer vector ${vector.name}`, () => {
    if (vector.error !== undefined) {
      assert.throws(() => parseTrailers(vector.message), (err: unknown) => {
        return err instanceof TrailerError && err.message.includes(vector.error as string);
      });
      return;
    }
    assert.deepEqual(parseTrailers(vector.message), vector.links);
  });
}
