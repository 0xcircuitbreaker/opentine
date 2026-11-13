/** The slice of pako's low-level zlib port the browser `node:zlib` stand-in uses. */

declare module "pako/lib/zlib/zstream.js" {
  export default class ZStream {
    input: Uint8Array | null;
    next_in: number;
    avail_in: number;
    output: Uint8Array | null;
    next_out: number;
    avail_out: number;
    msg: string;
  }
}

declare module "pako/lib/zlib/inflate.js" {
  import type ZStream from "pako/lib/zlib/zstream.js";
  export function inflateInit(strm: ZStream): number;
  export function inflate(strm: ZStream, flush: number): number;
  export function inflateEnd(strm: ZStream): number;
}
