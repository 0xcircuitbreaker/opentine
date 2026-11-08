/**
 * Browser stand-in for `node:zlib`. Inflate in a browser is asynchronous
 * (`DecompressionStream`), so the synchronous reader cannot use it: the browser
 * entry (`./entry.ts`) inflates a zlib-wrapped artifact before verifying it, and
 * any other synchronous inflate is refused here (the caller reports it).
 */

export function inflateSync(): never {
  throw new Error("synchronous zlib inflate is not available in the browser verifier");
}
