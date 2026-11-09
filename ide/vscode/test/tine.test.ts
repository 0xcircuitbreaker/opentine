import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test } from "node:test";

import { parseBlame } from "../src/blame.js";
import { explain, parseVerdict, parseWhy, verifyArgs, whyArgs } from "../src/provenance.js";
import { parseJson, repoRelative, runTine } from "../src/tine.js";

const FAKE = [process.execPath, path.join(__dirname, "..", "..", "test", "fixtures", "fake-tine.cjs")];

test("the fake tine answers blame through an argument list, no shell", async () => {
  const log = path.join(mkdtempSync(path.join(tmpdir(), "opentine-vscode-")), "argv.json");
  process.env.FAKE_TINE_LOG = log;
  try {
    const odd = "src/a file; echo $HOME.py";
    await runTine(FAKE, ["blame", odd, "--lines", "--json"], process.cwd());
    assert.deepEqual(JSON.parse(readFileSync(log, "utf-8")), ["blame", odd, "--lines", "--json"]);
  } finally {
    delete process.env.FAKE_TINE_LOG;
  }
  const record = parseBlame(parseJson(await runTine(FAKE, ["blame", "src/app.py"], process.cwd())));
  assert.equal(record.aiLines, 2);
});

test("why then verify: the provenance of one line, end to end", async () => {
  const why = parseWhy(parseJson(await runTine(FAKE, whyArgs("src/app.py", 2), process.cwd())));
  const verdict = parseVerdict(parseJson(await runTine(FAKE, verifyArgs(why.run), process.cwd())));
  assert.match(explain(why, verdict), /claude-sonnet-4-5 .*verified offline: pass/);
  process.env.FAKE_TINE_TAMPERED = "1";
  try {
    const result = await runTine(FAKE, verifyArgs(why.run), process.cwd());
    assert.equal(result.code, 4);
    assert.equal(parseVerdict(parseJson(result)).ok, false);
  } finally {
    delete process.env.FAKE_TINE_TAMPERED;
  }
});

test("an error envelope and a missing executable are errors, not verdicts", async () => {
  await assert.rejects(async () => parseJson(await runTine(FAKE, ["bogus"], process.cwd())), /unknown verb bogus/);
  await assert.rejects(runTine([path.join(tmpdir(), "no-such-tine-here")], ["why"], process.cwd()), /cannot run/);
});

test("paths reach tine repository-relative and POSIX on every platform", () => {
  assert.equal(repoRelative("/w", "/w/src/app.py", "/"), "src/app.py");
  assert.equal(repoRelative("C:\\w", "C:\\w\\src\\app.py", "\\"), "src/app.py");
  assert.throws(() => repoRelative("/w", "/other/x.py", "/"), /not inside/);
});
