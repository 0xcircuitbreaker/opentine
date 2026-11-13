// Debug aid: run the harness conformance bundle in Node and print rows that
// differ from the Node build (`node src/node-run.mjs`).

import { existsSync, readdirSync, readFileSync, statSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildConformance } from "./build.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SUITE = join(ROOT, "docs", "conformance");
const out = {};
const add = (path) => (out[`/repo/${relative(ROOT, path).split("\\").join("/")}`] = readFileSync(path).toString("base64"));
const walk = (dir) => readdirSync(dir).forEach((n) => (statSync(join(dir, n)).isDirectory() ? walk(join(dir, n)) : add(join(dir, n))));
walk(SUITE);
for (const name of Object.keys(JSON.parse(readFileSync(join(SUITE, "MANIFEST.json"), "utf8")).files)) {
  add(existsSync(join(SUITE, name)) ? join(SUITE, name) : join(ROOT, name));
}
const file = join(mkdtempSync(join(tmpdir(), "conf-")), "conformance.js");
await buildConformance(file);
const mod = await import(pathToFileURL(file).href);
const rows = mod.runConformance(out);
const { loadSuite, runSuite } = await import(pathToFileURL(join(ROOT, "ts", "verifier", "dist", "src", "suite.js")).href);
const expected = runSuite(loadSuite(ROOT));
for (let i = 0; i < rows.length; i++) {
  const a = rows[i];
  const b = expected[i];
  if (a.status !== b.status || a.reason !== b.reasonActual) console.log(a.id, a.status, a.reason, "| node", b.status, b.reasonActual, "|", a.detail.slice(0, 200));
}
console.log(rows.length, "rows");
