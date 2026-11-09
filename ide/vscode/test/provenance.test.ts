import { strict as assert } from "node:assert";
import { test } from "node:test";

import { blameArgs, explain, parseVerdict, parseWhy, verifyArgs, whyArgs } from "../src/provenance.js";

const RUN = "run:sha256:" + "be".repeat(32);

test("the argument lists are the CLI's, with a POSIX FILE:LINE", () => {
  assert.deepEqual(whyArgs("src/app.py", 2), ["why", "src/app.py:2", "--json"]);
  assert.deepEqual(blameArgs("src/app.py"), ["blame", "src/app.py", "--lines", "--json"]);
  assert.deepEqual(verifyArgs(RUN), ["verify", RUN, "--offline", "--json"]);
  assert.throws(() => whyArgs("a", 0), /start at 1/);
  assert.throws(() => verifyArgs("--help"), /never starts/);
});

test("a line with no run says so, and is never called verified", () => {
  const text = explain(parseWhy({ path: "a.py", line: 3, commit: "", run: "", slice: [] }), null);
  assert.match(text, /no agent run is linked/);
});

test("a verified, an unverifiable and a failed run are worded apart", () => {
  const found = parseWhy({ path: "a.py", line: 3, commit: "c".repeat(40), run: RUN, slice: [{}, {}],
                           attribution: { model: "m" } });
  assert.match(explain(found, parseVerdict({ verdict: "pass", checks: [] })), /verified offline: pass/);
  assert.match(explain(found, null), /not held here, so it was not verified/);
  const failed = parseVerdict({ verdict: "fail", checks: [{ outcome: "fail", reason: "integrity.mismatch" }] });
  assert.equal(failed.ok, false);
  assert.match(explain(found, failed), /FAILED \(integrity\.mismatch\)/);
});
