// The pinned conformance runner (ts/verifier/src/suite.ts), built for a browser
// with the same `node:crypto`, `node:zlib` and `Buffer` stand-ins as the
// shipped tine-verifier.js, plus an in-memory `node:fs` holding the suite.

import { install } from "./memfs.js";
import { loadSuite, runSuite } from "../../verifier/src/suite.ts";

export const ROOT = "/repo";

export function runConformance(files) {
  install(files);
  return runSuite(loadSuite(ROOT)).map((row) => ({
    id: row.id,
    status: row.status,
    reason: row.reasonActual,
    detail: row.detail,
  }));
}
