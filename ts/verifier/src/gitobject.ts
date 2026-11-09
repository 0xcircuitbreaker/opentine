/**
 * SPEC 4.18: check that bytes are the git object an id names. The id is the
 * hash of `<type> SP <length> NUL <bytes>`: SHA-1 for 40-hex ids, SHA-256 for
 * 64-hex ids. Returns the ids a tree, commit or tag links, so a caller can walk
 * a mirrored history. A port of `opentine._git_object.check`; plain SHA-1 (no
 * SHA-1DC). Browser-safe: `node:crypto`'s `createHash` resolves to the
 * `@noble/hashes` stand-in in the browser bundle.
 */

import { createHash } from "node:crypto";
import { TineError } from "./errors.js";

export const GIT_TYPES = ["blob", "tree", "commit", "tag"];
export const GIT_LABEL = "matches its id (checked by you)";
const HEX = /^([0-9a-f]{40}|[0-9a-f]{64})$/;
const MODE = /^[0-7]{5,6}$/;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function malformed(message: string): never {
  throw new TineError(`git object is malformed: ${message}`, "git-object.malformed");
}

const toHex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function treeLinks(data: Uint8Array, width: number): string[] {
  const out: string[] = [];
  let at = 0;
  while (at < data.length) {
    const space = data.indexOf(0x20, at);
    const nul = space >= 0 ? data.indexOf(0x00, space + 1) : -1;
    if (space < 0 || nul < 0 || nul === space + 1) malformed("a tree entry is <mode> SP <name> NUL <id>");
    const mode = String.fromCharCode(...data.subarray(at, space));
    if (!MODE.test(mode)) malformed("a tree entry is <mode> SP <name> NUL <id>");
    const name = data.subarray(space + 1, nul);
    const text = String.fromCharCode(...name);
    if (name.includes(0x2f) || text === "." || text === "..") malformed("a tree entry name is one path component");
    const raw = data.subarray(nul + 1, nul + 1 + width);
    if (raw.length !== width) malformed("a tree entry id is truncated");
    out.push(toHex(raw));
    at = nul + 1 + width;
  }
  return out;
}

function headerLinks(kind: string, data: Uint8Array, width: number, fmt: string): string[] {
  let end = data.length;
  for (let i = 0; i + 1 < data.length; i++) {
    if (data[i] === 0x0a && data[i + 1] === 0x0a) {
      end = i;
      break;
    }
  }
  let text: string;
  try {
    text = decoder.decode(data.subarray(0, end));
  } catch {
    malformed("headers are UTF-8");
  }
  const headers = text
    .split("\n")
    .filter((line) => line.includes(" "))
    .map((line) => [line.slice(0, line.indexOf(" ")), line.slice(line.indexOf(" ") + 1)]);
  const first = kind === "commit" ? "tree" : "object";
  if (headers.length === 0 || headers[0][0] !== first) malformed(`a ${kind} starts with a ${first} header`);
  const found = [headers[0][1]];
  if (kind === "commit") for (const [name, value] of headers.slice(1)) if (name === "parent") found.push(value);
  if (!found.every((oid) => oid.length === width * 2 && HEX.test(oid))) malformed(`a ${kind} links ${fmt} ids`);
  return found;
}

export interface GitObjectResult {
  oid: string;
  type: string;
  object_format: string;
  links: string[];
  state: string;
  label: string;
}

export function checkGitObject(kind: unknown, data: Uint8Array, oid: unknown): GitObjectResult {
  if (typeof oid !== "string" || !HEX.test(oid)) malformed("the id is 40 or 64 lowercase hex");
  if (typeof kind !== "string" || !GIT_TYPES.includes(kind)) malformed(`type is one of ${GIT_TYPES.join(", ")}`);
  if (data.length > 64 * 1024 * 1024) malformed("the object exceeds 64 MiB");
  const fmt = oid.length === 40 ? "sha1" : "sha256";
  const head = encoder.encode(`${kind} ${data.length}\u0000`);
  const framed = new Uint8Array(head.length + data.length);
  framed.set(head);
  framed.set(data, head.length);
  if (createHash(fmt).update(framed).digest("hex") !== oid) {
    throw new TineError(`the bytes do not hash to ${kind} ${oid}`, "git-object.mismatch");
  }
  const width = fmt === "sha1" ? 20 : 32;
  const links = kind === "blob" ? [] : kind === "tree" ? treeLinks(data, width) : headerLinks(kind, data, width, fmt);
  return { oid, type: kind, object_format: fmt, links, state: "matches", label: GIT_LABEL };
}
