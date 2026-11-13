/** A Node `ByteSource` over a file: positioned reads, never the whole file in memory. */

import { closeSync, fstatSync, openSync, readSync } from "node:fs";
import type { ByteSource } from "./bundlepack.js";

export function fileSource(path: string): ByteSource & { close(): void } {
  const fd = openSync(path, "r");
  const size = fstatSync(fd).size;
  return {
    size,
    read: async (offset, length) => {
      const out = new Uint8Array(Math.max(0, Math.min(length, size - offset)));
      let at = 0;
      while (at < out.length) {
        const got = readSync(fd, out, at, out.length - at, offset + at);
        if (got === 0) break;
        at += got;
      }
      return out.subarray(0, at);
    },
    close: () => closeSync(fd),
  };
}
