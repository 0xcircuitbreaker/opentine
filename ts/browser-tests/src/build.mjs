// Builds the harness-only browser bundle of the conformance runner into OUT
// (a temporary directory; never committed). Same aliases as
// ts/run-viewer/build-verifier.mjs, plus in-memory fs/path/util.

import { build } from "esbuild";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const browser = join(here, "..", "..", "verifier", "src", "browser");

export async function buildConformance(outfile) {
  await build({
    absWorkingDir: here,
    entryPoints: [join(here, "conformance-entry.js")],
    outfile,
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2020",
    charset: "utf8",
    alias: {
      "node:crypto": join(browser, "crypto.ts"),
      "node:zlib": join(browser, "zlib.ts"),
      "node:fs": join(here, "memfs.js"),
      "node:path": join(here, "path.js"),
      "node:util": join(here, "util.js"),
    },
    inject: [join(browser, "buffer.ts")],
    logLevel: "warning",
  });
}
