/**
 * 0.51: the browser build verifies what Node verifies.
 *
 * For each engine Playwright can launch here (Chromium, Firefox, WebKit; an
 * engine that is not installed is skipped with the reason):
 *
 *  1. the full pinned conformance set runs through a browser build of the
 *     conformance runner (the shipped stand-ins for node:crypto, node:zlib and
 *     Buffer) and every row's status and reason code equals Node's;
 *  2. every bundle of the Python-built corpus (tests/_bundle_corpus.py) is
 *     verified by the committed opentine/data/ui/tine-verifier.js, streamed
 *     from a Blob, with Node's verdict, reason, refs and digests, and Python's
 *     verdict;
 *  3. the committed run-viewer page checks a picked bundle and a record in its
 *     Web Worker and shows pass / fail / unchecked per check;
 *  4. with OPENTINE_BROWSER_LARGE=1, a generated bundle of at least 200 MiB is
 *     verified from a File with zero network requests.
 *
 * Needs `npm run build` in ts/verifier (the Node reference) and the repo's
 * Python environment (OPENTINE_PYTHON, else .venv) for the corpus.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative, resolve } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildConformance } from "../src/build.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..", "..");
const UI = join(ROOT, "opentine", "data", "ui");
const DIST = join(ROOT, "ts", "verifier", "dist", "src");
const SUITE = join(ROOT, "docs", "conformance");
const LARGE_MIB = Number(process.env.OPENTINE_BROWSER_LARGE_MIB || "210");
if (!process.env.PLAYWRIGHT_BROWSERS_PATH && existsSync("/opt/pw-browsers")) {
  process.env.PLAYWRIGHT_BROWSERS_PATH = "/opt/pw-browsers";
}
const { chromium, firefox, webkit } = await import("playwright-core");
const ENGINES = { chromium, firefox, webkit };

const work = mkdtempSync(join(tmpdir(), "opentine-browser-"));
const python = process.env.OPENTINE_PYTHON ||
  [join(ROOT, ".venv", "bin", "python"), join(ROOT, ".venv", "Scripts", "python.exe")].find(existsSync) || "python3";

function runPython(...args) {
  const done = spawnSync(python, ["-m", "tests._bundle_corpus", ...args], { cwd: ROOT, encoding: "utf8", timeout: 600_000 });
  return done.status === 0 ? null : `the Python corpus could not be built: ${(done.stderr || done.error?.message || "").slice(-400)}`;
}

const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json" };
let server;
let base;
const harness = join(work, "harness");

before(async () => {
  await buildConformance(join(harness, "conformance.js"));
  writeFileSync(join(harness, "blank.html"), '<!doctype html><meta charset="utf-8"><title>harness</title><input type="file" id="pick">');
  server = createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
    const file = path.startsWith("/harness/") ? join(harness, path.slice(9)) : join(UI, path === "/" ? "index.html" : path.slice(1));
    if (path.startsWith("/api/") || !existsSync(file) || !statSync(file).isFile()) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { "content-type": MIME[extname(file)] || "application/octet-stream" }).end(readFileSync(file));
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server?.close();
  rmSync(work, { recursive: true, force: true });
});

function suiteFiles() {
  const out = {};
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else out[`/repo/${relative(ROOT, path).split("\\").join("/")}`] = readFileSync(path).toString("base64");
    }
  };
  walk(SUITE);
  // Files the vectors read by repository path (MANIFEST.json lists them with digests).
  const manifest = JSON.parse(readFileSync(join(SUITE, "MANIFEST.json"), "utf8"));
  for (const name of Object.keys(manifest.files)) {
    const local = join(SUITE, name);
    const path = existsSync(local) ? local : join(ROOT, name);
    out[`/repo/${relative(ROOT, path).split("\\").join("/")}`] = readFileSync(path).toString("base64");
  }
  return out;
}

async function nodeRows() {
  const { loadSuite, runSuite } = await import(pathToFileURL(join(DIST, "suite.js")).href);
  return runSuite(loadSuite(ROOT)).map((row) => ({ id: row.id, status: row.status, reason: row.reasonActual }));
}

const corpusDir = join(work, "corpus");
let corpusSkip = null;
function corpus() {
  if (!existsSync(join(corpusDir, "verdicts.json")) && corpusSkip === null) corpusSkip = runPython(corpusDir);
  return corpusSkip;
}

const pick = (report) => ({ ok: report.ok, reason: report.reason, code: report.code, refs: report.refs, objects: report.objects, pack: report.pack, bundle: report.bundle });

function unavailable(name) {
  try {
    const path = ENGINES[name].executablePath();
    return existsSync(path) ? null : `${name} is not installed (${path}); npx playwright install ${name}`;
  } catch (exc) {
    return `${name} is not available: ${exc.message.split("\n")[0]}`;
  }
}

const distSkip = existsSync(join(DIST, "suite.js")) ? null : "ts/verifier is not built (npm run build in ts/verifier)";

for (const name of Object.keys(ENGINES)) {
  const skip = unavailable(name);
  describe(name, { skip: skip ?? distSkip ?? false }, () => {
    let browser;
    before(async () => {
      browser = await ENGINES[name].launch();
    });
    after(async () => {
      await browser?.close();
    });

    test("the full pinned conformance set gives Node's verdicts", { timeout: 600_000 }, async () => {
      const page = await browser.newPage();
      await page.goto(`${base}/harness/blank.html`);
      const rows = await page.evaluate(async (files) => {
        const mod = await import("/harness/conformance.js");
        return mod.runConformance(files);
      }, suiteFiles());
      const expected = await nodeRows();
      assert.equal(rows.length, expected.length);
      assert.ok(rows.length > 900, `${rows.length} rows`);
      const key = ({ id, status, reason }) => JSON.stringify([id, status, reason]);
      const differ = rows.filter((row, i) => key(row) !== key(expected[i]));
      assert.deepEqual(differ.map((row) => `${row.id}: browser ${row.status}/${row.reason}: ${row.detail.slice(0, 160)}`), []);
      await page.close();
    });

    test("every corpus bundle gives Node's and Python's verdict, streamed from a Blob", { timeout: 600_000 }, async (t) => {
      const why = corpus();
      if (why) return t.skip(why);
      const verdicts = JSON.parse(readFileSync(join(corpusDir, "verdicts.json"), "utf8"));
      const files = Object.fromEntries(Object.keys(verdicts).map((key) => [key, readFileSync(join(corpusDir, `${key}.bundle`)).toString("base64")]));
      const page = await browser.newPage();
      await page.goto(`${base}/harness/blank.html`);
      const seen = await page.evaluate(async (bundles) => {
        const mod = await import("/tine-verifier.js");
        const out = {};
        for (const [key, b64] of Object.entries(bundles)) {
          const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
          out[key] = await mod.verifyBundle(mod.blobSource(new Blob([bytes])));
        }
        return out;
      }, files);
      const { verifyBundle } = await import(pathToFileURL(join(DIST, "bundle.js")).href);
      const { bytesSource } = await import(pathToFileURL(join(DIST, "bundlepack.js")).href);
      for (const [key, want] of Object.entries(verdicts)) {
        const node = await verifyBundle(bytesSource(new Uint8Array(readFileSync(join(corpusDir, `${key}.bundle`)))));
        assert.deepEqual(pick(seen[key]), pick(node), key);
        assert.equal(seen[key].ok, want.ok, `${key}: Python says ${want.ok} (${want.reason})`);
        if (want.ok) {
          assert.deepEqual(seen[key].refs, want.refs, key);
          assert.equal(seen[key].pack, want.pack, key);
          assert.equal(seen[key].bundle, want.bundle, key);
          assert.deepEqual(seen[key].content_unavailable, want.content_unavailable, key);
        } else if (want.reason) {
          assert.equal(seen[key].reason.split(":")[0], want.reason.split(":")[0], key);
        }
      }
      await page.close();
    });

    test("the run viewer checks a picked file in its worker, per check", { timeout: 300_000 }, async (t) => {
      const why = corpus();
      if (why) return t.skip(why);
      const page = await browser.newPage();
      await page.goto(`${base}/`);
      const check = async (file) => {
        await page.setInputFiles("#verify-file", file);
        const verdict = page.locator("#file-verdict");
        await verdict.waitFor({ timeout: 120_000 });
        const rows = await page.locator("tr[data-state]").evaluateAll((trs) => trs.map((tr) => [tr.children[0].textContent, tr.dataset.state]));
        const result = { verdict: await verdict.getAttribute("data-verdict"), rows };
        await page.evaluate(() => document.getElementById("file-verdict")?.remove());
        return result;
      };
      const good = await check(join(corpusDir, "signed-ed25519.bundle"));
      assert.equal(good.verdict, "pass");
      assert.ok(good.rows.some(([what, state]) => what === "signature sidecars" && state === "pass"));
      assert.ok(good.rows.some(([what, state]) => what === "transparency receipts" && state === "unchecked"));
      const bad = await check(join(corpusDir, "signed-tampered.bundle"));
      assert.equal(bad.verdict, "fail");
      assert.ok(bad.rows.every(([, state]) => state !== "pass" || bad.rows.length > 1));
      const hmac = await check(join(corpusDir, "redacted-public-hmac.bundle"));
      assert.ok(hmac.rows.some(([what, state]) => what === "redacted-copy record" && state === "unchecked"));
      await page.close();
    });

    test(`a ${LARGE_MIB} MiB bundle verifies from a File with zero network requests`, { timeout: 1_800_000 }, async (t) => {
      if (process.env.OPENTINE_BROWSER_LARGE !== "1") return t.skip("set OPENTINE_BROWSER_LARGE=1 to generate and verify a >= 200 MiB bundle");
      const file = join(work, "large.bundle");
      if (!existsSync(file)) {
        const why = runPython("--large", file, String(LARGE_MIB));
        if (why) return t.skip(why);
      }
      assert.ok(statSync(file).size >= 200 * 1024 * 1024);
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(`${base}/harness/blank.html`);
      await page.evaluate(async () => {
        globalThis.tv = await import("/tine-verifier.js");
      });
      await page.setInputFiles("#pick", file);
      const requests = [];
      context.on("request", (request) => requests.push(request.url()));
      const report = await page.evaluate(async () => {
        const picked = document.getElementById("pick").files[0];
        const out = await globalThis.tv.verifyBundle(globalThis.tv.blobSource(picked));
        return { ok: out.ok, reason: out.reason, objects: out.objects };
      });
      assert.deepEqual(requests, []);
      // Control: the listener does see this page's requests.
      await page.evaluate(() => fetch("/harness/blank.html").then((res) => res.text()));
      assert.equal(requests.length, 1);
      assert.equal(report.ok, true, report.reason);
      assert.equal(report.objects, LARGE_MIB + 1);
      await context.close();
    });
  });
}
