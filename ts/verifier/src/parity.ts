/**
 * The TS verifier's half of the three-way parity check (0.50, ROADMAP criterion 2).
 *
 * `node dist/src/parity.js [REPO_ROOT]` runs every case of `docs/conformance`
 * and prints one JSON line per case: `{id, file, op, status, reason, detail}`,
 * where `status` is this verifier's score against the pinned answer (`pass`,
 * `fail`, `repaired`, `unsupported`, or `skip` for the writer-side redaction
 * ops it does not implement). `scripts/check_parity.py` reads these lines next
 * to the Python reference and the built `tine-verify.pyz` and fails on any
 * disagreement.
 */

import { resolve } from "node:path";
import { loadSuite, runSuite } from "./suite.js";

const root = resolve(process.argv[2] ?? ".");
for (const row of runSuite(loadSuite(root))) {
  const line = { id: row.id, file: row.file, op: row.op, status: row.status, reason: row.reasonActual, detail: row.detail };
  process.stdout.write(JSON.stringify(line) + "\n");
}
