// A stand-in for the `tine` CLI: canned `--json` answers, keyed by the verb.
// It records the argument list it got so the test can check nothing went
// through a shell.
const fs = require("node:fs");
const path = require("node:path");

const args = process.argv.slice(2);
const [verb] = args;
if (process.env.FAKE_TINE_LOG) fs.writeFileSync(process.env.FAKE_TINE_LOG, JSON.stringify(args));
const run = "run:sha256:be292c795e4d4c484dd65313e8556098ce724bdc7bae5722c6125c49c651db36";
if (verb === "blame") {
  process.stdout.write(fs.readFileSync(path.join(__dirname, "blame-lines.json"), "utf-8"));
} else if (verb === "why") {
  process.stdout.write(JSON.stringify({
    command: "why", path: "src/app.py", line: 2, commit: "8f2c1d4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d",
    linked_runs: [run], run, attribution: { run, seq: 4, model: "claude-sonnet-4-5" },
    slice: [{ seq: 3 }, { seq: 4 }],
  }));
} else if (verb === "verify") {
  const tampered = process.env.FAKE_TINE_TAMPERED === "1";
  process.stdout.write(JSON.stringify({
    schema: "tine-verify-report/2", verdict: tampered ? "fail" : "pass", ok: !tampered,
    checks: [{ name: "integrity", outcome: tampered ? "fail" : "pass", reason: tampered ? "integrity.mismatch" : "integrity.ok" }],
  }));
  process.exitCode = tampered ? 4 : 0;
} else {
  process.stdout.write(JSON.stringify({ error: { code: "usage", exit_code: 2, message: `unknown verb ${verb}` } }));
  process.exitCode = 2;
}
