/**
 * The browser build of the verifier: what `tine ui` (and opentine-web) load as
 * `tine-verifier.js` to re-check a run in the viewer's own browser.
 *
 * `verifyArtifact(raw)` runs the same `.tine` v4/v5 check as the CLI
 * (`verifyBytes`): every envelope id, the root, the annotation chain and the
 * `tine-sig/3` blocks. No key is pinned in a browser, so an Ed25519 signature is
 * checked under the key the file embeds (`verified-tofu`) and an HMAC one cannot
 * be checked (`no-key`). A zlib-wrapped file is inflated here first, with
 * `DecompressionStream`, under the same declared-length rule as the reader.
 * Since 0.51 `verifyBundle(blobSource(file))` checks a `tine bundle` file as
 * `tine bundle verify` does, streamed with `Blob.slice`, and `verifyRecord`
 * checks one signed record by its kind.
 */

import { isWrapped, MAGIC, MAX_TINE_ARTIFACT_BYTES, readUvarint } from "../codec.js";
import { verifyBytes, type Report } from "../verify.js";

export { verifyRedactionReport } from "../redactreport.js";
export { checkGitObject } from "../gitobject.js"; // SPEC 4.18 (0.46.1)
export { projectDigest, verifyMirrorState, verifyProject, verifyProjectChain } from "../project.js";
export { verifyReview, verifyReviewBundle, verifyReviewGate } from "../review.js"; // SPEC 4.20 (0.47)
// 0.51: bundles streamed from a File, every 0.46-0.50 record family, and the release this build is for.
export { blobSource, bytesSource, isBundle, verifyBundle, verifyBundleBytes, type BundleKeys, type BundleReport, type Check } from "../bundle.js";
export { recordKinds, verifyRecord, verifyRecordBytes, type RecordCheck } from "../recordcheck.js";
export { OPENTINE_VERSION } from "../version.js";
export type { Report };

/** The Compression Streams API surface used here (the verifier compiles without DOM types). */
interface Streams {
  DecompressionStream?: new (format: string) => {
    readable: { getReader(): { read(): Promise<{ done: boolean; value: Uint8Array }>; cancel(): Promise<void> } };
    writable: { getWriter(): { write(chunk: Uint8Array): Promise<void>; close(): Promise<void> } };
  };
}

/** The inflated body of a codec-1 (zlib) wrapped file; `null` when *raw* is not one. */
async function inflated(raw: Uint8Array): Promise<Uint8Array | null> {
  if (!isWrapped(raw) || raw.length <= MAGIC.length || raw[MAGIC.length] !== 1) return null;
  const [size, offset] = readUvarint(raw, MAGIC.length + 1);
  if (size > MAX_TINE_ARTIFACT_BYTES) throw new Error("compressed body declares more bytes than the reader allows");
  const Stream = (globalThis as unknown as Streams).DecompressionStream;
  if (!Stream) throw new Error("this browser cannot inflate zlib");
  const stream = new Stream("deflate");
  const writer = stream.writable.getWriter();
  void writer.write(raw.subarray(offset)).then(() => writer.close()).catch(() => undefined);
  const out = new Uint8Array(size);
  let at = 0;
  const reader = stream.readable.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (at + value.length > size) {
      await reader.cancel();
      throw new Error("compressed body does not match its declared length");
    }
    out.set(value, at);
    at += value.length;
  }
  if (at !== size) throw new Error("compressed body does not match its declared length");
  if (isWrapped(out)) throw new Error("nested compression is not allowed");
  return out;
}

/** The CLI's report for one artifact's bytes, checked in this runtime. */
export async function verifyArtifact(raw: Uint8Array, name = "artifact"): Promise<Report> {
  let body = raw;
  try {
    body = (await inflated(raw)) ?? raw;
  } catch (exc) {
    return {
      schema: "opentine-verify-ts/1",
      path: name,
      verdict: "fail",
      ok: false,
      format: null,
      root: null,
      integrity: { ok: false, reason: (exc as Error).message },
      signature: null,
    };
  }
  return verifyBytes(body, name, { trustEmbedded: true });
}
export { verifyMemory, verifyPrompt } from "../registry.js";
