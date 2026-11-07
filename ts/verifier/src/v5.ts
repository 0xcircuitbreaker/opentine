/**
 * `.tine` v5 (SPEC Part 10): a v4 document whose UTF-8 text blobs travel as JSON
 * strings. A port of `opentine/_tine_v5.py`: `v5ToV4` rebuilds the v4 document
 * the v5 one spells, so every oid, the root and every `tine-sig/3` block are the
 * v4 ones; the v4 reader then checks it unchanged. Messages match the Python
 * reference byte for byte, because verdict vectors compare them.
 */

import { TineError } from "./errors.js";
import { hasLoneSurrogate, isObject, type JObject, type JValue } from "./json.js";

export const V5_KIND = "tine-artifact/5";
const V4_KIND = "tine-artifact/4";
const TEXT_KEYS = ["encoding", "schema", "type", "text"];
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function isV5Artifact(data: unknown): data is JObject {
  return isObject(data) && data.get("format_version") === 5n && data.get("kind") === V5_KIND;
}

/** True when `body` is well-formed UTF-8 (RFC 3629): what a v5 writer spells as text. */
export function isUtf8Text(body: Uint8Array): boolean {
  try {
    STRICT_UTF8.decode(body);
    return true;
  } catch {
    return false;
  }
}

function base64Body(data: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(data) || data.length % 4 !== 0) return null;
  return Uint8Array.from(Buffer.from(data, "base64"));
}

function entryToV4(entry: JValue, where: string): JValue {
  if (!isObject(entry)) return entry; // the v4 reader names the malformed envelope
  if (entry.get("encoding") === "text") {
    const exact = entry.size === TEXT_KEYS.length && TEXT_KEYS.every((key) => entry.has(key));
    if (!exact || entry.get("type") !== "blob") {
      throw new TineError(`${where}: a v5 text envelope is encoding, schema, type=blob and text`);
    }
    const text = entry.get("text");
    if (typeof text !== "string") throw new TineError(`${where}: v5 blob text must be a string`);
    if (hasLoneSurrogate(text)) throw new TineError(`${where}: v5 blob text holds a lone surrogate`);
    return new Map<string, JValue>([
      ["data", Buffer.from(text, "utf8").toString("base64")],
      ["encoding", "raw"],
      ["schema", entry.get("schema") as JValue],
      ["type", "blob"],
    ]);
  }
  const data = entry.get("data");
  if (entry.get("encoding") === "raw" && typeof data === "string") {
    const body = base64Body(data);
    if (body !== null && isUtf8Text(body)) {
      throw new TineError(`${where}: UTF-8 text must be spelled as v5 text, not base64`);
    }
  }
  return entry;
}

/** The v4 document a v5 document spells (SPEC 10.3); throws if a spelling is not v5's. */
export function v5ToV4(data: JObject): JObject {
  const out = new Map(data);
  out.set("format_version", 4n);
  out.set("kind", V4_KIND);
  const objects = data.get("objects");
  if (isObject(objects)) {
    out.set("objects", new Map([...objects].map(([oid, entry]) => [oid, entryToV4(entry, `objects[${oid}]`)])));
  }
  return out;
}

/** `data` unchanged unless it is a v5 document, which is re-spelled as v4. */
export function asV4(data: JValue): JValue {
  return isV5Artifact(data) ? v5ToV4(data) : data;
}
