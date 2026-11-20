/**
 * 0.69 (F2) history merge: a port of `opentine._history_merge.merge` and
 * `opentine._history_merge_record.check`.
 *
 * A snapshot (`opentine-history-snapshot/1`) holds refs, label states, lineage
 * records and holds; the merge is three-way and symmetric, conflicts keep the
 * base value and holds are only ever added. A merge is recorded as an
 * attestation under the `opentine.history-merge/1` claim convention; `check`
 * re-runs the merge from the three snapshots, compares digests and conflicts
 * with the claim and checks the signature. A CLI-level check outside the
 * frozen vector families: `verify` gives the claim no verdict. Shared fixture:
 * tests/data/history_merge.json.
 */

import { canonicalJson, canonicalText } from "./canon.js";
import { sha256Hex } from "./crypto.js";
import { codePointCompare, isObject, type JObject, type JValue } from "./json.js";
import { verifyAttestation } from "./signature.js";

export const FORMAT = "opentine-history-snapshot/1";
export const CONVENTION = "opentine.history-merge/1";
const DOMAIN = new TextEncoder().encode("opentine.history-snapshot.v1:");
const CLAIM = ["convention", "base", "sides", "merged", "conflicts", "target"];
const GUARDS = ["loop-stop:", "integrity-taint:", "memory-quarantine:"];
export const KINDS = ["ref-diverged", "label-moved", "promotion-diverged", "lineage-id", "hold-weakened",
  "held-target"];
const RUN = /^run:sha256:[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]{64}$/;
// Label names and lineage ids become file names on apply: only these shapes.
const LABEL_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const LINEAGE_ID = /^sha256:[0-9a-f]{64}$/;

type Label = { current: string | null; history: string[] };
export interface Snapshot {
  refs: Map<string, string>; labels: Map<string, Label>; lineage: Map<string, string>; holds: [string, string][];
}
export interface Conflict { kind: string; key: string; base: JValue; sides: JValue[] }
export interface MergeResult {
  merged: Snapshot; conflicts: Conflict[]; digests: { base: string; sides: string[]; merged: string };
}
export interface HistoryMergeCheck {
  ok: boolean; signature: string; merged: string; merged_matches: boolean; conflicts_match: boolean; conflicts: number;
}

const NONE: Label = { current: null, history: [] };
const bad = (why: string): Error => new Error(`history-merge.malformed: ${why}`);
const keysSorted = (...maps: Map<string, unknown>[]): string[] =>
  [...new Set(maps.flatMap((m) => [...m.keys()]))].sort(codePointCompare);

function bytesCompare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
const canonCompare = (a: JValue, b: JValue): number => bytesCompare(canonicalJson(a), canonicalJson(b));
const same = (a: JValue, b: JValue): boolean => canonicalText(a) === canonicalText(b);

function strMap(value: JValue | undefined, name: string): Map<string, string> {
  if (!isObject(value)) throw bad(`${name} maps names to strings`);
  for (const [k, v] of value) if (!k || typeof v !== "string" || !v) throw bad(`${name} maps names to strings`);
  return new Map(value as Map<string, string>);
}

export function normalize(value: JValue): Snapshot {
  if (!isObject(value) || value.get("format") !== FORMAT || value.size !== 5) throw bad("not a snapshot");
  for (const k of ["refs", "labels", "lineage", "holds"]) if (!value.has(k)) throw bad("not a snapshot");
  const labels = new Map<string, Label>();
  const raw = value.get("labels");
  if (!isObject(raw)) throw bad("labels is an object");
  for (const [name, state] of raw) {
    if (!LABEL_NAME.test(name)) throw bad("label names are [a-z0-9][a-z0-9._-]{0,63}");
    if (!isObject(state) || state.size !== 2 || !state.has("current") || !state.has("history")) throw bad("label");
    const current = state.get("current");
    const history = state.get("history");
    if (current !== null && typeof current !== "string") throw bad("label current");
    if (!Array.isArray(history) || !history.every((h) => typeof h === "string")) throw bad("label history");
    labels.set(name, { current: current as string | null, history: [...(history as string[])] });
  }
  const holds = value.get("holds");
  if (!Array.isArray(holds) || !holds.every((h) => Array.isArray(h) && h.length === 2 && h.every((x) => typeof x === "string"))) {
    throw bad("holds is a list of pairs");
  }
  const pairs = new Map((holds as string[][]).map((h) => [canonicalText(h), [h[0], h[1]] as [string, string]]));
  if (pairs.size !== holds.length) throw bad("holds are unique");
  const lineage = strMap(value.get("lineage"), "lineage");
  for (const k of lineage.keys()) if (!LINEAGE_ID.test(k)) throw bad("lineage ids are sha256:HEX");
  return { refs: strMap(value.get("refs"), "refs"), labels, lineage,
    holds: sortPairs([...pairs.values()]) };
}

function sortPairs(pairs: [string, string][]): [string, string][] {
  return pairs.sort((a, b) => codePointCompare(a[0], b[0]) || codePointCompare(a[1], b[1]));
}

function labelValue(l: Label): JObject {
  return new Map<string, JValue>([["current", l.current], ["history", [...l.history]]]);
}

export function toJson(s: Snapshot): JObject {
  const refs = new Map<string, JValue>(s.refs);
  const labels = new Map<string, JValue>([...s.labels].map(([k, v]) => [k, labelValue(v)]));
  return new Map<string, JValue>([["format", FORMAT], ["refs", refs], ["labels", labels],
    ["lineage", new Map<string, JValue>(s.lineage)], ["holds", s.holds.map((h) => [...h])]]);
}

export function digest(s: Snapshot): string {
  const tail = canonicalJson(toJson(s));
  const message = new Uint8Array(DOMAIN.length + tail.length);
  message.set(DOMAIN);
  message.set(tail, DOMAIN.length);
  return `sha256:${sha256Hex(message)}`;
}

function row(kind: string, key: string, base: JValue, a: JValue, b: JValue): Conflict {
  return { kind, key, base, sides: [a, b].sort(canonCompare) };
}

function pick<T extends JValue>(base: T, a: T, b: T): [T, boolean] {
  if (same(a, b)) return [a, false];
  if (same(a, base)) return [b, false];
  if (same(b, base)) return [a, false];
  return [base, true];
}

const prefix = (longer: string[], shorter: string[]): boolean =>
  longer.length >= shorter.length && shorter.every((h, i) => longer[i] === h);

export function merge(baseIn: JValue, oursIn: JValue, theirsIn: JValue): MergeResult {
  const [b, o, t] = [normalize(baseIn), normalize(oursIn), normalize(theirsIn)];
  const rows: Conflict[] = [];
  const holdSet = (s: Snapshot): Set<string> => new Set(s.holds.map((h) => canonicalText(h)));
  const [hb, ho, ht] = [holdSet(b), holdSet(o), holdSet(t)];
  const all = new Map([...b.holds, ...o.holds, ...t.holds].map((h) => [canonicalText(h), h]));
  const guarded = new Set<string>();
  for (const [k, [target, oid]] of all) {
    if (GUARDS.some((g) => target.startsWith(g))) {
      guarded.add(oid);
      guarded.add(target.slice(target.indexOf(":") + 1));
    }
  }
  const refs = new Map<string, string>();
  for (const name of keysSorted(b.refs, o.refs, t.refs)) {
    const vb = b.refs.get(name) ?? null;
    const vo = o.refs.get(name) ?? vb;
    const vt = t.refs.get(name) ?? vb;
    let [value, clash] = pick<string | null>(vb, vo, vt);
    if (clash) rows.push(row("ref-diverged", name, vb, vo, vt));
    else if (value !== vb && value !== null && guarded.has(value)) {
      rows.push(row("held-target", `refs/${name}`, vb, vo, vt));
      value = vb;
    }
    if (value !== null) refs.set(name, value);
  }
  const labels = new Map<string, Label>();
  for (const name of keysSorted(b.labels, o.labels, t.labels)) {
    const [sb, so, st] = [b, o, t].map((s) => s.labels.get(name) ?? NONE);
    const [jb, jo, jt] = [sb, so, st].map(labelValue);
    let state: Label;
    if (!(prefix(so.history, sb.history) && prefix(st.history, sb.history)) ||
        !(prefix(so.history, st.history) || prefix(st.history, so.history))) {
      rows.push(row("promotion-diverged", name, jb, jo, jt));
      state = sb;
    } else {
      const [current, clash] = pick<string | null>(sb.current, so.current, st.current);
      state = { current, history: [...(so.history.length >= st.history.length ? so.history : st.history)] };
      if (clash) {
        rows.push(row("label-moved", name, jb, jo, jt));
        state = sb;
      } else if (current !== sb.current && current !== null && guarded.has(current)) {
        rows.push(row("held-target", `labels/${name}`, jb, jo, jt));
        state = sb;
      }
    }
    if (!same(labelValue(state), labelValue(NONE))) labels.set(name, { current: state.current, history: [...state.history] });
  }
  const lineage = new Map<string, string>();
  for (const ident of keysSorted(b.lineage, o.lineage, t.lineage)) {
    const values = [b, o, t].map((s) => s.lineage.get(ident) ?? null);
    const found = new Set(values.filter((v): v is string => v !== null));
    if (found.size > 1) {
      rows.push(row("lineage-id", ident, values[0], values[1], values[2]));
      if (values[0] !== null) lineage.set(ident, values[0]);
    } else lineage.set(ident, [...found][0]);
  }
  for (const [target, oid] of b.holds) {
    const k = canonicalText([target, oid]);
    if (!(ho.has(k) && ht.has(k))) rows.push(row("hold-weakened", target, oid, ho.has(k), ht.has(k)));
  }
  const merged: Snapshot = { refs, labels, lineage, holds: sortPairs([...all.values()].map((h) => [h[0], h[1]])) };
  rows.sort((x, y) => KINDS.indexOf(x.kind) - KINDS.indexOf(y.kind) || codePointCompare(x.key, y.key) ||
    canonCompare(conflictJson(x), conflictJson(y)));
  const sides = [digest(o), digest(t)].sort(canonCompare);
  return { merged, conflicts: rows, digests: { base: digest(b), sides, merged: digest(merged) } };
}

export function conflictJson(c: Conflict): JObject {
  return new Map<string, JValue>([["kind", c.kind], ["key", c.key], ["base", c.base], ["sides", c.sides]]);
}

function signature(record: JObject, publicKey: Uint8Array | null): [boolean, string] {
  const block = record.get("signature");
  if (!isObject(block)) return [false, "unsigned"];
  const key = block.get("public_key");
  if (block.get("alg") !== "ed25519" || typeof key !== "string" || !HEX.test(key)) return [false, "error"];
  if (`sha256:${sha256Hex(Uint8Array.from(Buffer.from(key, "hex")))}` !== record.get("signer")) return [false, "mismatch"];
  const found = verifyAttestation(record, publicKey ? { publicKey } : { trustEmbedded: true });
  return [found.ok, found.state];
}

export function checkHistoryMerge(record: JValue, base: JValue, ours: JValue, theirs: JValue,
  publicKey: Uint8Array | null = null): HistoryMergeCheck {
  const claim = isObject(record) ? record.get("claim") : undefined;
  if (!isObject(record) || !isObject(claim) || claim.get("convention") !== CONVENTION) throw bad("not a history-merge claim");
  if (claim.size !== CLAIM.length || !CLAIM.every((k) => claim.has(k)) || !Array.isArray(claim.get("conflicts"))) {
    throw bad("the claim's fields");
  }
  const target = record.get("target_id");
  if (typeof target !== "string" || !RUN.test(target)) throw bad("the record targets a run");
  const result = merge(base, ours, theirs);
  const d = result.digests;
  const mergedOk = claim.get("merged") === d.merged && claim.get("base") === d.base && same(claim.get("sides") as JValue, d.sides);
  const conflictsOk = same(claim.get("conflicts") as JValue, result.conflicts.map(conflictJson));
  const [signed, state] = signature(record, publicKey);
  return { ok: signed && mergedOk && conflictsOk, signature: state, merged: d.merged, merged_matches: mergedOk,
    conflicts_match: conflictsOk, conflicts: result.conflicts.length };
}
