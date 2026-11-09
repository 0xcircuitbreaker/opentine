/**
 * SPEC 4.19 (0.47): run merge and pick, `opentine.merge` (merge/v1) and
 * `opentine.merge-approval`. A port of `opentine/_merge.py`
 * (`merge_payloads`, `pick_payloads`), `opentine/_merge_tree.py` (the
 * three-way tree merge and the nested tree encoding) and
 * `opentine/_merge_record.py` (`check`, `check_approval`), so the same two run
 * payloads give the same merge oids here as in Python. Refusals carry
 * `merge.*` and `merge-approval.*` codes.
 */

import { canonicalJson } from "./canon.js";
import { ObjectEnvelope, objectId, parseOid } from "./envelope.js";
import { TineError } from "./errors.js";
import { isObject, pyEqual, type JObject, type JValue } from "./json.js";
import { signed, type Kind } from "./records.js";

const EMPTY_EVENT: [string, JValue][] = [
  ["billing", new Map()],
  ["causal_ids", []],
  ["cost", 0n],
  ["duration", 0n],
  ["error", new Map()],
  ["model", ""],
  ["tool", new Map()],
  ["usage", new Map()],
];
const LEAF_MODES = new Set(["100644", "100755", "120000"]);
const NAME = /^[A-Za-z0-9_.:/@+-]{1,256}$/;
const WHEN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const RUN = /^run:sha256:[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

function malformed(message: string): never {
  throw new TineError(`merge input is malformed: ${message}`, "merge.malformed");
}

export function runOid(payload: JValue): string {
  return ObjectEnvelope.create("run", payload).oid;
}

function strings(value: JValue | undefined): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function uniq(rows: string[]): string[] {
  return [...new Set(rows)];
}

function events(payload: JValue, side: string): string[] {
  if (!isObject(payload) || !Array.isArray(payload.get("events"))) malformed(`${side} is not a run`);
  const run = payload as JObject;
  const rows = run.get("events");
  if (!strings(rows) || rows.length === 0 || new Set(rows).size !== rows.length) malformed(`${side} events`);
  for (const field of ["tips", "roots"]) {
    const value = run.get(field);
    if (!Array.isArray(value) || !value.every((item) => typeof item === "string" && rows.includes(item))) {
      malformed(`${side} ${field}`);
    }
  }
  return rows;
}

function isNumber(value: JValue | undefined): value is bigint | number {
  return typeof value === "bigint" || typeof value === "number";
}

/** Python `max` over the numeric `created_at`s (the first maximal one), else 0. */
function when(...payloads: JObject[]): JValue {
  let best: bigint | number | null = null;
  for (const payload of payloads) {
    const value = payload.get("created_at");
    if (isNumber(value) && (best === null || Number(value) > Number(best))) best = value;
  }
  return best === null ? 0n : best;
}

/** The leaves of the union of two runs' event graphs (ours' tips first). */
function leaves(ours: JObject, theirs: JObject): string[] {
  const inner = new Set<string>();
  for (const side of [ours, theirs]) {
    const tips = side.get("tips") as string[];
    for (const event of side.get("events") as string[]) if (!tips.includes(event)) inner.add(event);
  }
  return uniq([...(ours.get("tips") as string[]), ...(theirs.get("tips") as string[])]).filter((e) => !inner.has(e));
}

function blobOid(value: JValue, schema = 1n): string {
  return objectId("blob", schema, canonicalJson(value));
}

const utf8 = (text: string) => Buffer.from(text, "utf8");
const byUtf8 = (a: string, b: string) => Buffer.compare(utf8(a), utf8(b));

type Flat = Map<string, JObject>;

function checkFlat(flat: JValue | undefined): Flat {
  if (flat === null || flat === undefined) return new Map();
  if (!isObject(flat)) malformed("a flat tree is an object of path -> leaf");
  const out: Flat = new Map();
  for (const [path, leaf] of flat as JObject) {
    if (!isObject(leaf) || [...leaf.keys()].some((key) => !["mode", "oid", "redacted"].includes(key))) malformed(`malformed tree leaf: ${path}`);
    const node = leaf as JObject;
    if (!LEAF_MODES.has(node.get("mode") as string) || (node.has("redacted") && node.get("redacted") !== true)) {
      malformed(`malformed tree leaf: ${path}`);
    }
    try {
      parseOid(node.get("oid"));
    } catch {
      malformed(`malformed tree leaf: ${path}`);
    }
    const parts = path.split("/");
    if (!path || parts.some((p) => p === "" || p === "." || p === ".." || p.includes("\\") || p.includes("\0"))) {
      malformed(`invalid tree path: ${path}`);
    }
    out.set(path, node);
  }
  return out;
}

function mergeFlat(baseIn: JValue | undefined, oursIn: JValue, theirsIn: JValue): [Flat, JObject[]] {
  const base = checkFlat(baseIn);
  const ours = checkFlat(oursIn);
  const theirs = checkFlat(theirsIn);
  const merged: Flat = new Map();
  const conflicts: JObject[] = [];
  const oid = (leaf: JObject | undefined): JValue => (leaf ? (leaf.get("oid") as string) : null);
  const same = (a: JObject | undefined, b: JObject | undefined) => (a === undefined || b === undefined ? a === b : pyEqual(a, b));
  const paths = [...new Set([...base.keys(), ...ours.keys(), ...theirs.keys()])].sort(byUtf8);
  for (const path of paths) {
    const b = base.get(path);
    const o = ours.get(path);
    const t = theirs.get(path);
    let take: JObject | undefined;
    if (same(o, t) || same(t, b)) take = o;
    else if (same(o, b)) take = t;
    else {
      take = o;
      conflicts.push(new Map<string, JValue>([["kind", "tree"], ["path", path], ["base", oid(b)], ["ours", oid(o)], ["theirs", oid(t)]]));
    }
    if (take !== undefined) merged.set(path, take);
  }
  for (const path of merged.keys()) {
    for (const other of merged.keys()) if (other.startsWith(path + "/")) malformed(`tree merge puts a file and a directory at ${path}`);
  }
  return [merged, conflicts];
}

function encodeTrees(flat: Flat): string {
  const build = (rows: Flat): string => {
    const files: JObject[] = [];
    const dirs = new Map<string, Flat>();
    for (const [path, leaf] of rows) {
      const cut = path.indexOf("/");
      if (cut >= 0) {
        const head = path.slice(0, cut);
        if (!dirs.has(head)) dirs.set(head, new Map());
        dirs.get(head)!.set(path.slice(cut + 1), leaf);
      } else {
        files.push(new Map([...leaf, ["name", path]]));
      }
    }
    for (const [name, sub] of dirs) files.push(new Map<string, JValue>([["mode", "40000"], ["name", name], ["oid", build(sub)]]));
    files.sort((a, b) => byUtf8(a.get("name") as string, b.get("name") as string));
    return blobOid(new Map<string, JValue>([["entries", files], ["type", "opentine.tree"]]), 2n);
  };
  return build(flat);
}

/** SPEC 4.19 `merge.compute`: `{run, event, tree, status, conflicts}`. */
export function mergeCompute(value: JObject): Record<string, unknown> {
  const oursIn = value.get("ours") as JValue;
  const theirsIn = value.get("theirs") as JValue;
  const oursEvents = events(oursIn, "ours");
  const theirsEvents = events(theirsIn, "theirs");
  const ours = oursIn as JObject;
  const theirs = theirsIn as JObject;
  const oursOid = runOid(ours);
  const theirsOid = runOid(theirs);
  if (oursOid === theirsOid) throw new TineError("cannot merge a run with itself", "merge.same-run");
  if (theirsEvents.every((e) => oursEvents.includes(e))) {
    throw new TineError("theirs is already contained in ours: up to date", "merge.up-to-date");
  }
  const common = oursEvents.filter((e) => theirsEvents.includes(e));
  const union = [...common, ...oursEvents.filter((e) => !theirsEvents.includes(e)), ...theirsEvents.filter((e) => !oursEvents.includes(e))];
  const conflicts: JObject[] = [];
  let tree: string | null = null;
  const trees = value.get("trees");
  const treeMap = isObject(trees) ? trees : new Map<string, JValue>();
  const oursTree = treeMap.get("ours");
  const theirsTree = treeMap.get("theirs");
  if (oursTree !== null && oursTree !== undefined && theirsTree !== null && theirsTree !== undefined) {
    const [flat, found] = mergeFlat(treeMap.get("base"), oursTree, theirsTree);
    tree = encodeTrees(flat);
    conflicts.push(...found);
  }
  const mine = (ours.get("manifests") as JObject | undefined) ?? new Map();
  const other = (theirs.get("manifests") as JObject | undefined) ?? new Map();
  const policy = (m: JObject) => (isObject(m) ? (m.get("policy") ?? null) : null);
  if (!pyEqual(policy(mine), policy(other))) {
    conflicts.push(new Map<string, JValue>([["kind", "manifest"], ["name", "policy"], ["base", null], ["ours", policy(mine)], ["theirs", policy(other)]]));
  }
  const output = blobOid(new Map<string, JValue>([["conflicts", conflicts], ["merged", [oursOid, theirsOid]], ["type", "opentine.merge"]]));
  const at = when(ours, theirs);
  const event: JObject = new Map<string, JValue>([...EMPTY_EVENT, ["kind", "merge"], ["output_blob", output], ["parent_ids", leaves(ours, theirs)], ["time_unix", at]]);
  if (tree !== null) event.set("tree", tree);
  const eventOid = ObjectEnvelope.create("event", event).oid;
  const status = conflicts.length ? "paused" : "completed";
  const run: JObject = new Map([...ours].filter(([key]) => key !== "forked_from" && key !== "parents"));
  run.set("events", [...union, eventOid]);
  run.set("roots", uniq([...(ours.get("roots") as string[]), ...(theirs.get("roots") as string[])]));
  run.set("tips", [eventOid]);
  run.set("parents", [oursOid, theirsOid]);
  run.set("created_at", at);
  run.set("status", status);
  const plain = (row: JObject) => Object.fromEntries(row);
  return { run: runOid(run), event: eventOid, tree, status, conflicts: conflicts.map(plain) };
}

/** SPEC 4.19 `merge.pick`: `{run, events}`. */
export function mergePick(value: JObject): Record<string, unknown> {
  const oursIn = value.get("ours") as JValue;
  const rows = [...events(oursIn, "ours")];
  const ours = oursIn as JObject;
  const picks = value.get("picks");
  const fail = (message: string): never => {
    throw new TineError(message, "merge.malformed");
  };
  if (!Array.isArray(picks) || picks.length === 0) fail("pick needs at least one event");
  const held = new Set(rows);
  const mapping = new Map<string, string>();
  let tips = [...(ours.get("tips") as string[])];
  const written: string[] = [];
  for (const row of picks as JValue[]) {
    const [source, payload] = row as [string, JValue];
    if (!isObject(payload) || held.has(source)) fail(`cannot pick ${source}: already in the run`);
    const body = payload as JObject;
    if (ObjectEnvelope.create("event", body).oid !== source) fail(`cannot pick ${source}: payload is another event`);
    if (mapping.has(source)) fail(`cannot pick ${source} twice`);
    const links = body.get("causal_ids") ?? [];
    if (!strings(links)) fail(`cannot pick ${source}: malformed causal_ids`);
    const causal = (links as string[]).map((c) => mapping.get(c) ?? c);
    const copy: JObject = new Map(body);
    copy.set("parent_ids", tips);
    copy.set("picked_from", source);
    copy.set("causal_ids", uniq(causal.filter((c) => held.has(c))));
    const oid = ObjectEnvelope.create("event", copy).oid;
    if (held.has(oid)) fail(`picking ${source} adds nothing`);
    mapping.set(source, oid);
    held.add(oid);
    rows.push(oid);
    tips = [oid];
    written.push(oid);
  }
  const run: JObject = new Map([...ours].filter(([key]) => key !== "forked_from" && key !== "parents"));
  run.set("events", rows);
  run.set("tips", tips);
  run.set("forked_from", runOid(ours));
  return { run: runOid(run), events: written };
}

function count(value: JValue | undefined): boolean {
  if (typeof value === "bigint") return value >= 0n && value < 2n ** 53n;
  return false;
}

function text(value: JValue | undefined, pattern: RegExp): boolean {
  return typeof value === "string" && pattern.test(value);
}

const MERGE: Kind = {
  code: "merge",
  subject: "merge record",
  domain: "opentine.merge.v1:",
  fields: ["kind", "merge_version", "run", "parents", "target", "fencing", "gates", "conflicts", "actor", "merged_at"],
};
const APPROVAL: Kind = {
  code: "merge-approval",
  subject: "merge-approval record",
  domain: "opentine.merge-approval.v1:",
  fields: ["kind", "approval_version", "run", "target", "decision", "approver", "approved_at"],
};

function mergeRule(body: JObject): string | null {
  if (body.get("kind") !== "opentine.merge") return "kind is not opentine.merge";
  if (body.get("merge_version") !== 1n) return "merge_version must be 1";
  const parents = body.get("parents");
  if (!text(body.get("run"), RUN) || !Array.isArray(parents) || parents.length < 2 || parents.length > 64) {
    return "run must be a run oid and parents two or more run oids";
  }
  if (!parents.every((p) => text(p, RUN)) || new Set(parents).size !== parents.length) return "parents must be unique run oids";
  if (parents.includes(body.get("run") as string)) return "a merge cannot be its own parent";
  if (body.get("target") !== null && !text(body.get("target"), NAME)) return "target must be a ref name or null";
  if (body.get("fencing") !== null && !count(body.get("fencing"))) return "fencing must be a count or null";
  const gates = body.get("gates");
  if (!Array.isArray(gates) || gates.length > 256) return "gates must be a list";
  for (const gate of gates) {
    if (!isObject(gate) || gate.size !== 2 || !gate.has("gate") || !gate.has("digest")) return "a gate is {gate, digest}";
    if (!["vsa", "eval", "approval"].includes(gate.get("gate") as string) || !text(gate.get("digest"), DIGEST)) {
      return "a gate names vsa, eval or approval and a sha256 digest";
    }
  }
  if (!count(body.get("conflicts"))) return "conflicts must be a count";
  if (!text(body.get("actor"), NAME)) return "actor must be a name";
  if (!text(body.get("merged_at"), WHEN)) return "merged_at must be an RFC 3339 UTC time";
  return null;
}

function approvalRule(body: JObject): string | null {
  if (body.get("kind") !== "opentine.merge-approval") return "kind is not opentine.merge-approval";
  if (body.get("approval_version") !== 1n) return "approval_version must be 1";
  if (!text(body.get("run"), RUN)) return "run must be a run oid";
  if (!text(body.get("target"), NAME) || !text(body.get("approver"), NAME)) return "target and approver must be names";
  if (!["approve", "reject"].includes(body.get("decision") as string)) return "decision must be approve or reject";
  if (!text(body.get("approved_at"), WHEN)) return "approved_at must be an RFC 3339 UTC time";
  return null;
}

/** SPEC 4.19 `merge.verify`: `{run, parents, target, fencing, state}`. */
export function verifyMerge(record: JValue, hmacKey?: Uint8Array | null, publicKey?: Uint8Array | null, run?: JValue): Record<string, unknown> {
  const { body, state } = signed(MERGE, record, mergeRule, hmacKey, publicKey);
  if (run !== undefined && run !== null) {
    if (!isObject(run) || runOid(run) !== body.get("run")) throw new TineError("the merge record names another run", "merge.run-mismatch");
    if (!pyEqual(run.get("parents"), body.get("parents"))) throw new TineError("the merged run has other parents", "merge.run-mismatch");
  }
  const fencing = body.get("fencing");
  return {
    run: body.get("run"),
    parents: body.get("parents"),
    target: body.get("target"),
    fencing: typeof fencing === "bigint" ? Number(fencing) : null,
    state,
  };
}

/** SPEC 4.19 `merge-approval.verify`: `{run, target, decision, approver, state}`. */
export function verifyMergeApproval(record: JValue, hmacKey?: Uint8Array | null, publicKey?: Uint8Array | null): Record<string, unknown> {
  const { body, state } = signed(APPROVAL, record, approvalRule, hmacKey, publicKey);
  return { run: body.get("run"), target: body.get("target"), decision: body.get("decision"), approver: body.get("approver"), state };
}
