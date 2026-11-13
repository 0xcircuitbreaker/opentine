/**
 * Browser stand-in for `node:zlib`'s `inflateSync`, on pako's low-level zlib
 * port (0.51). It keeps the parts of Node's contract the verifier relies on:
 * `maxOutputLength` refuses with `ERR_BUFFER_TOO_LARGE`, a stream that ends
 * early refuses with `Z_BUF_ERROR`, corrupt data with `Z_DATA_ERROR`, and with
 * `info: true` the result reports `engine.bytesWritten` (the input consumed),
 * so trailing bytes after the stream are caught by the caller exactly as under
 * Node. Only one zlib stream is read; pako's multi-stream convenience is not
 * used.
 */

import { inflate, inflateEnd, inflateInit } from "pako/lib/zlib/inflate.js";
import ZStream from "pako/lib/zlib/zstream.js";

const Z_FINISH = 4;
const Z_OK = 0;
const Z_STREAM_END = 1;
const Z_BUF_ERROR = -5;
const CHUNK = 64 * 1024;

function refusal(code: string, message: string): Error {
  return Object.assign(new Error(message), { code });
}

interface Options {
  info?: boolean;
  maxOutputLength?: number;
}

export function inflateSync(data: Uint8Array, options: Options = {}): unknown {
  const limit = options.maxOutputLength ?? Number.MAX_SAFE_INTEGER;
  const strm = new ZStream();
  if (inflateInit(strm) !== Z_OK) throw refusal("Z_DATA_ERROR", "zlib init failed");
  strm.input = data;
  strm.next_in = 0;
  strm.avail_in = data.length;
  const chunks: Uint8Array[] = [];
  let total = 0;
  let status = Z_OK;
  try {
    for (;;) {
      const out = new Uint8Array(CHUNK);
      strm.output = out;
      strm.next_out = 0;
      strm.avail_out = CHUNK;
      status = inflate(strm, Z_FINISH);
      const produced = CHUNK - strm.avail_out;
      if (produced) {
        total += produced;
        if (total > limit) throw refusal("ERR_BUFFER_TOO_LARGE", "output exceeds maxOutputLength");
        chunks.push(out.subarray(0, produced));
      }
      if (status === Z_STREAM_END) break;
      if (status === Z_BUF_ERROR && strm.avail_in === 0) throw refusal("Z_BUF_ERROR", "unexpected end of file");
      if (status !== Z_OK && status !== Z_BUF_ERROR) throw refusal("Z_DATA_ERROR", strm.msg || "invalid data");
      if (produced === 0 && strm.avail_in === 0) throw refusal("Z_BUF_ERROR", "unexpected end of file");
    }
  } finally {
    inflateEnd(strm);
  }
  const buffer = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, at);
    at += chunk.length;
  }
  const result = Buffer.from(buffer);
  if (!options.info) return result;
  return { buffer: result, engine: { bytesWritten: data.length - strm.avail_in } };
}
