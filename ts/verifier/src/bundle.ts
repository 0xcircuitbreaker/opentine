/**
 * `tine bundle verify` in any runtime (0.51): a port of `opentine._bundle.verify`,
 * `_bundle_sigs.check`, `_bundle_extra.check` and `_bundle_share.verified`
 * over a streaming `ByteSource`, so a browser checks a large bundle from a
 * `File` without holding it: the bundle checksum, file digest and pack digest
 * are one incremental SHA-256 pass, and a `TINEPACK3` is matched one object at
 * a time (`bundlepack.ts`). Refusals carry Python's `BundleError` message and
 * a `bundle.*` reason code. Nothing here touches the network.
 *
 * Layout: `TINEBUNDLE1\n | sha256(body) | body`, `body = u32be len | manifest | pack`.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesEqual, canonicalJson, validateJsonShape } from "./canon.js";
import { parseOid } from "./envelope.js";
import { TineError } from "./errors.js";
import { isObject, KERNEL, parseBytes, type JObject, type JValue } from "./json.js";
import { inspectPack, MAX_PACK_BYTES } from "./pack.js";
import { verifyRedactedCopy, wellFormed } from "./records.js";
import { normalizeRef, validateRefTarget } from "./repo.js";
import { artifactMessage, verifyBlock } from "./signature.js";
import { bytesSource, hexOf, ranges, streamV3, type ByteSource } from "./bundlepack.js";
import { OPENTINE_VERSION } from "./version.js";

export { blobSource, bytesSource, type ByteSource } from "./bundlepack.js";

export const BUNDLE_MAGIC = new TextEncoder().encode("TINEBUNDLE1\n");
export const BUNDLE_FORMAT = "opentine-bundle/1";
export const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
export const MAX_REFS = 10_000;
export const MAX_BUNDLE_BYTES = BUNDLE_MAGIC.length + 32 + 4 + MAX_MANIFEST_BYTES + MAX_PACK_BYTES;
export const BUNDLE_REPORT_SCHEMA = "opentine-bundle-verify-ts/1";
const KEYS = ["format", "pack", "pack_bytes", "refs"];
const OPTIONAL = ["signatures", "transparency", "tombstones", "redacted_public"];
const BLOCK_KEYS = new Set(["alg", "key_id", "scheme", "signed_at", "signer", "value", "public_key"]);
const MAX_SIDECAR_ENTRIES = 256;
const MAX_BLOCK_BYTES = 16 * 1024;

export type CheckState = "pass" | "fail" | "unchecked";
export interface Check {
  name: string;
  state: CheckState;
  reason: string;
}

export interface BundleReport {
  schema: string;
  opentine_version: string;
  verdict: "pass" | "fail";
  ok: boolean;
  reason: string | null;
  code: string | null;
  bundle: string | null;
  pack: string | null;
  objects: number;
  /** `streamed` (TINEPACK3, constant memory per object) or `in-memory` (TINEPACK5/4, or a refusal's exact reason). */
  pack_reader: "streamed" | "in-memory" | null;
  refs: Record<string, string>;
  signatures: number;
  transparency: number;
  content_unavailable: string[];
  redacted_public: Record<string, unknown> | null;
  checks: Check[];
}

const refuse = (message: string, code: string): never => {
  throw new TineError(message, code);
};

function manifestOf(raw: Uint8Array): JObject {
  let payload: JValue;
  try {
    validateJsonShape(raw);
    payload = parseBytes(raw, KERNEL, "bundle manifest");
  } catch (exc) {
    return refuse(`invalid bundle manifest: ${(exc as Error).message}`, "bundle.manifest-invalid");
  }
  if (!bytesEqual(canonicalJson(payload), raw)) refuse("invalid bundle manifest: bundle manifest is not canonical", "bundle.manifest-invalid");
  const keys = isObject(payload) ? [...payload.keys()].filter((key) => !OPTIONAL.includes(key)) : [];
  if (!isObject(payload) || keys.length !== KEYS.length || !KEYS.every((key) => keys.includes(key))) {
    refuse("invalid bundle manifest shape", "bundle.manifest-shape");
  }
  const manifest = payload as JObject;
  const format = manifest.get("format");
  if (format !== BUNDLE_FORMAT) refuse(`unsupported bundle format: '${String(format).slice(0, 40)}'`, "bundle.format-unsupported");
  const refs = manifest.get("refs");
  if (!isObject(refs ?? null) || (refs as JObject).size > MAX_REFS) refuse("invalid or excessive bundle refs", "bundle.refs-invalid");
  return manifest;
}

function checkRefs(manifest: JObject, present: Set<string>): Record<string, string> {
  const refs: Record<string, string> = {};
  const tracked = new Map<string, string>();
  for (const [name, oid] of manifest.get("refs") as JObject) {
    try {
      let normalized = "";
      try {
        normalized = normalizeRef(name);
      } catch {
        normalized = "";
      }
      if (normalized !== name || name.startsWith("remotes/") || typeof oid !== "string") throw new Error(`invalid ref name: '${name}'`);
      parseOid(oid);
      validateRefTarget(name, oid, new Map());
    } catch (exc) {
      refuse(`unsafe bundle ref: ${(exc as Error).message}`, "bundle.ref-unsafe");
    }
    if (!present.has(oid as string)) refuse(`bundle ref ${name} points outside the bundle`, "bundle.ref-outside");
    const key = name.startsWith("heads/") ? name.slice(6) : name;
    const other = tracked.get(key) ?? name;
    tracked.set(key, other);
    if (other !== name) refuse(`bundle refs ${other} and ${name} collide on one tracking ref`, "bundle.ref-collision");
    refs[name] = oid as string;
  }
  return refs;
}

function checkSignatures(value: JValue, present: Set<string>): number {
  const bad = (message: string): never => refuse(`invalid bundle signatures: ${message}`, "bundle.signatures-invalid");
  if (!isObject(value)) bad("not an object");
  let count = 0;
  for (const [root, entries] of value as JObject) {
    try {
      if (parseOid(root)[0] !== "run") bad("a key is not a run oid");
    } catch (exc) {
      if ((exc as TineError).code?.startsWith("bundle.")) throw exc;
      bad((exc as Error).message);
    }
    if (!present.has(root)) bad(`${root} is not in the bundle`);
    if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_SIDECAR_ENTRIES) bad(`${root} must hold 1..${MAX_SIDECAR_ENTRIES} entries`);
    for (const entry of entries as JValue[]) {
      if (!isObject(entry) || entry.size !== 2 || !entry.has("annotations_head") || !entry.has("block")) bad("an entry is not {annotations_head, block}");
      const head = (entry as JObject).get("annotations_head") as JValue;
      const block = (entry as JObject).get("block") as JValue;
      if (head !== null) {
        let kind = "";
        try {
          kind = typeof head === "string" ? parseOid(head)[0] : "";
        } catch (exc) {
          bad((exc as Error).message);
        }
        if (kind !== "annotation") bad("annotations_head is not an annotation oid");
      }
      if (!isObject(block) || block.get("scheme") !== "tine-sig/3") bad("a block is not tine-sig/3");
      if ([...(block as JObject).keys()].some((key) => !BLOCK_KEYS.has(key))) bad("a block has unknown keys");
      if (canonicalJson(block).length > MAX_BLOCK_BYTES) bad(`a block exceeds ${MAX_BLOCK_BYTES} bytes`);
      if ((block as JObject).get("alg") === "ed25519") {
        const view: JObject = new Map<string, JValue>([
          ["annotations", head ? [new Map<string, JValue>([["id", head]])] : []],
          ["root", root],
        ]);
        const verdict = verifyBlock(block, (header) => artifactMessage(view, header), ["tine-sig/3"], "bundle signature", { trustEmbedded: true });
        if (verdict.state === "mismatch" || verdict.state === "error") bad(`a block for ${root} does not verify: ${verdict.reason}`);
      }
      count++;
    }
  }
  return count;
}

function checkExtra(manifest: JObject, shallow: string[], refs: Record<string, string>): JValue[] {
  const bad = (message: string): never => refuse(`invalid bundle ${message}`, "bundle.extra-invalid");
  const records = manifest.get("tombstones") ?? [];
  if (!Array.isArray(records) || records.length > 10_000) bad("tombstones: not a list of at most 10000 records");
  const boundary = new Set(shallow);
  const seen = new Set<string>();
  try {
    for (const record of records as JValue[]) {
      const oid = wellFormed("tombstone", record).get("oid") as string;
      if (!boundary.has(oid) || seen.has(oid)) bad(`tombstones: ${oid} is not a boundary of the pack, once`);
      seen.add(oid);
    }
    const copy = manifest.get("redacted_public");
    if (copy !== undefined) {
      const found = wellFormed("redacted-copy", copy);
      const objects = found.get("objects") as bigint;
      const redacted = found.get("redacted") as bigint;
      if (redacted > objects) throw new TineError("redacted exceeds objects", "redacted-copy.inconsistent");
      if ((redacted === 0n) !== (found.get("source_run") === found.get("public_run"))) {
        throw new TineError("the run oids must be equal exactly when no object was redacted", "redacted-copy.inconsistent");
      }
      if (found.get("pack") !== manifest.get("pack")) bad("redacted_public: the record names another pack");
      if (!Object.values(refs).includes(found.get("public_run") as string)) bad("redacted_public: the public run is not a bundled ref");
    }
  } catch (exc) {
    const code = (exc as TineError).code ?? "";
    if (code.startsWith("bundle.")) throw exc;
    bad(`0.46 record: ${code}: ${(exc as Error).message}`);
  }
  return records as JValue[];
}

/** One incremental pass: sha256(file), sha256(body) and sha256(pack). */
async function digests(source: ByteSource, packStart: number): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
  const file = sha256.create();
  const body = sha256.create();
  const pack = sha256.create();
  const bodyStart = BUNDLE_MAGIC.length + 32;
  let at = 0;
  for await (const chunk of ranges(source, 0, source.size)) {
    file.update(chunk);
    const from = Math.max(0, bodyStart - at);
    if (from < chunk.length) body.update(chunk.subarray(from));
    const packFrom = Math.max(0, packStart - at);
    if (packFrom < chunk.length) pack.update(chunk.subarray(packFrom));
    at += chunk.length;
  }
  return [file.digest(), body.digest(), pack.digest()];
}

async function verifyOrThrow(source: ByteSource, report: BundleReport): Promise<void> {
  const pass = (name: string, reason: string) => report.checks.push({ name, state: "pass", reason });
  if (source.size > MAX_BUNDLE_BYTES) refuse("bundle exceeds the maximum size", "bundle.oversized");
  const head = await source.read(0, Math.min(source.size, BUNDLE_MAGIC.length + 36));
  if (head.length < BUNDLE_MAGIC.length + 36 || !bytesEqual(head.subarray(0, BUNDLE_MAGIC.length), BUNDLE_MAGIC)) {
    refuse("not an opentine bundle (bad magic or truncated)", "bundle.bad-magic");
  }
  const expected = head.subarray(BUNDLE_MAGIC.length, BUNDLE_MAGIC.length + 32);
  const sizeAt = BUNDLE_MAGIC.length + 32;
  const size = new DataView(head.buffer, head.byteOffset + sizeAt, 4).getUint32(0);
  const packStart = sizeAt + 4 + size;
  const [file, body, pack] = await digests(source, Math.min(packStart, source.size));
  report.bundle = `sha256:${hexOf(file)}`;
  if (!bytesEqual(body, expected)) refuse("bundle checksum mismatch (truncated or tampered)", "bundle.checksum-mismatch");
  pass("bundle checksum", "sha256 of the body matches the header");
  if (size > MAX_MANIFEST_BYTES || packStart > source.size) refuse("bundle manifest length is invalid", "bundle.manifest-length");
  const manifest = manifestOf(await source.read(sizeAt + 4, size));
  pass("manifest", "canonical opentine-bundle/1 manifest");
  const packBytes = source.size - packStart;
  if (manifest.get("pack_bytes") !== BigInt(packBytes)) refuse("bundle pack length mismatch", "bundle.pack-length-mismatch");
  if (manifest.get("pack") !== `sha256:${hexOf(pack)}`) refuse("bundle pack digest mismatch", "bundle.pack-digest-mismatch");
  pass("pack digest", "the manifest's pack digest and length hold");
  let streamed = await streamV3(source, packStart, source.size);
  report.pack_reader = streamed ? "streamed" : "in-memory";
  if (!streamed) {
    try {
      const inspected = inspectPack(await source.read(packStart, packBytes));
      streamed = { packId: inspected.packId, oids: new Set(inspected.objects.map(([oid]) => oid)), shallow: inspected.shallow };
    } catch (exc) {
      refuse(`bundle pack is invalid: ${(exc as Error).message}`, `bundle.pack-invalid:${(exc as TineError).code ?? "error"}`);
    }
  }
  const inside = streamed!;
  report.pack = inside.packId;
  report.objects = inside.oids.size;
  pass("pack objects", `${inside.oids.size} objects, every id re-derived from its bytes`);
  report.refs = checkRefs(manifest, inside.oids);
  pass("refs", `${Object.keys(report.refs).length} refs, each a safe name inside the pack`);
  report.signatures = checkSignatures(manifest.get("signatures") ?? new Map(), inside.oids);
  pass("signature sidecars", report.signatures ? `${report.signatures} tine-sig/3 blocks; ed25519 under their embedded keys (unpinned)` : "none carried");
  const receipts = manifest.get("transparency") ?? [];
  if (!Array.isArray(receipts) || receipts.length > MAX_REFS) refuse("invalid bundle transparency receipts", "bundle.transparency-invalid");
  report.transparency = (receipts as JValue[]).length;
  if (report.transparency) report.checks.push({ name: "transparency receipts", state: "unchecked", reason: "receipts are shape-checked only here; check them with `tine verify --witnesses`" });
  const tombstones = checkExtra(manifest, inside.shallow, report.refs);
  report.content_unavailable = tombstones.map((record) => (record as JObject).get("oid") as string);
  if (tombstones.length) pass("tombstones", `${tombstones.length} purged boundaries, each well formed (signatures not checked without a key)`);
  const copy = manifest.get("redacted_public");
  if (copy !== undefined) report.redacted_public = redactedPublic(copy, report);
}

function redactedPublic(copy: JValue, report: BundleReport): Record<string, unknown> {
  const body = copy as JObject;
  const row: Record<string, unknown> = {};
  for (const key of ["source_run", "public_run", "objects", "redacted", "ruleset"]) {
    const value = body.get(key);
    row[key] = typeof value === "bigint" ? Number(value) : value;
  }
  if ((body.get("signature") as JObject).get("alg") === "hmac-sha256") {
    report.checks.push({ name: "redacted-copy record", state: "unchecked", reason: "an HMAC record needs the signer's key" });
    return { ...row, state: "unchecked", reason: null };
  }
  try {
    const found = verifyRedactedCopy(copy, null, null, body.get("pack") as string);
    report.checks.push({ name: "redacted-copy record", state: "pass", reason: `${found.state} (embedded key, unpinned)` });
    return { ...row, state: found.state, reason: null };
  } catch (exc) {
    const code = (exc as TineError).code;
    report.checks.push({ name: "redacted-copy record", state: "fail", reason: code });
    return { ...row, state: "failed", reason: code };
  }
}

/** Verify a bundle from any `ByteSource`; never throws. */
export async function verifyBundle(source: ByteSource): Promise<BundleReport> {
  const report: BundleReport = {
    schema: BUNDLE_REPORT_SCHEMA,
    opentine_version: OPENTINE_VERSION,
    verdict: "fail",
    ok: false,
    reason: null,
    code: null,
    bundle: null,
    pack: null,
    objects: 0,
    pack_reader: null,
    refs: {},
    signatures: 0,
    transparency: 0,
    content_unavailable: [],
    redacted_public: null,
    checks: [],
  };
  try {
    await verifyOrThrow(source, report);
    const failed = report.redacted_public?.state === "failed";
    report.ok = !failed;
    report.verdict = failed ? "fail" : "pass";
    if (failed) [report.reason, report.code] = ["the redacted-copy record does not verify", "bundle.redacted-public-failed"];
  } catch (exc) {
    report.reason = (exc as Error).message;
    report.code = (exc as TineError).code ?? "bundle.error";
    report.checks.push({ name: "bundle", state: "fail", reason: report.reason });
  }
  return report;
}

/** `verifyBundle` over bytes already in memory. */
export const verifyBundleBytes = (data: Uint8Array) => verifyBundle(bytesSource(data));

export function isBundle(head: Uint8Array): boolean {
  return head.length >= BUNDLE_MAGIC.length && bytesEqual(head.subarray(0, BUNDLE_MAGIC.length), BUNDLE_MAGIC);
}
