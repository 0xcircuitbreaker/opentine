/**
 * SPEC 1.5.2-1.5.6: the cross-object rules a full local read applies after an
 * envelope decodes: event metrics, the run event graph, annotation chains and
 * link existence. Ports of `opentine.repository._run_graph` and
 * `_annotations.validate_annotation_chain` over an in-memory object set.
 */

import { ObjectEnvelope, validateLinks } from "./envelope.js";
import { TineError } from "./errors.js";
import { isObject, MAX_SAFE, truthy, type JObject, type JValue } from "./json.js";

/** The smallest object store the cross-object validators need. */
export class MemRepo {
  readonly present: Set<string>;

  constructor(
    readonly objects: Map<string, Uint8Array>,
    present: Iterable<string> = [],
    readonly shallow: Set<string> = new Set(),
  ) {
    this.present = new Set([...present, ...objects.keys()]);
  }

  has(oid: string): boolean {
    return this.present.has(oid);
  }

  get(oid: string): ObjectEnvelope {
    const raw = this.objects.get(oid);
    if (raw === undefined) throw new TineError(`object is unavailable: ${oid}`, "link.missing-object");
    return ObjectEnvelope.decode(raw, oid);
  }
}

function payloadObject(envelope: ObjectEnvelope): JObject {
  const payload = envelope.payload();
  if (!isObject(payload)) {
    throw new TineError(`${envelope.objectType} payload must be an object`, "sig.payload-not-object");
  }
  return payload;
}

// --------------------------------------------------------------------------- //
// SPEC 1.5.2: event metrics
// --------------------------------------------------------------------------- //

const TOKEN_USAGE = new Set(["input", "output", "cache_read", "cache_write_5m", "cache_write_1h", "reasoning", "total"]);
const DECIMAL = /^[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?$/i;
const DECIMAL_SPECIAL = /^[+-]?(?:inf|infinity|s?nan\d*)$/i;

/**
 * Python `Decimal(str(value))` as a finite float, or `null` where CPython's
 * Decimal refuses the spelling or the value is not finite.
 */
function decimalValue(value: JValue | undefined): number | null {
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "string") return null;
  // Decimal strips surrounding whitespace and allows `_` between digits.
  const text = value.trim().replace(/(?<=\d)_(?=\d)/g, "");
  if (DECIMAL_SPECIAL.test(text)) return null;
  if (!DECIMAL.test(text)) return null;
  return Number(text);
}

function meter(value: JValue | undefined, label: string, nonnegative = true): void {
  if (typeof value === "string" && value.length > 128) {
    throw new TineError(`${label} must be finite and non-negative`, "metrics.meter-too-long");
  }
  const number = decimalValue(value);
  // Number() of a decimal string is finite exactly when CPython's float() is.
  if (number === null || !Number.isFinite(number) || (nonnegative && number < 0)) {
    throw new TineError(`${label} must be finite and non-negative`, "metrics.meter-not-finite");
  }
}

/** `_run_graph.validate_event_metrics`. */
export function validateEventMetrics(envelope: ObjectEnvelope): void {
  if (envelope.objectType !== "event") return;
  const payload = payloadObject(envelope);
  for (const field of ["cost", "duration"]) {
    meter(payload.has(field) ? payload.get(field) : 0n, `event ${field}`);
  }
  if (payload.has("time_unix")) meter(payload.get("time_unix"), "event time_unix", false);
  const usage = truthy(payload.get("usage")) ? payload.get("usage") : new Map();
  if (!isObject(usage)) throw new TineError("event usage must be a mapping", "metrics.usage-not-object");
  for (const [name, value] of usage) {
    if (typeof value !== "bigint" && typeof value !== "number") {
      throw new TineError(`event usage.${name} must be numeric`, "metrics.usage-value-not-numeric");
    }
    meter(value, `event usage.${name}`);
    const integral = typeof value === "bigint" ? value <= MAX_SAFE : Number.isInteger(value) && value <= Number(MAX_SAFE);
    if (TOKEN_USAGE.has(name) && !integral) {
      throw new TineError(`event usage.${name} must be a safe integer token count`, "metrics.token-dimension-unsafe");
    }
  }
}

// --------------------------------------------------------------------------- //
// SPEC 1.5.3: the run event graph
// --------------------------------------------------------------------------- //

const RUN_STATUSES = new Set(["running", "paused", "completed", "failed"]);

function list(value: JValue | undefined): JValue[] {
  return truthy(value) && Array.isArray(value) ? value : [];
}

function sameSet(a: JValue[], b: Set<string>): boolean {
  const left = new Set(a as string[]);
  return left.size === b.size && [...left].every((item) => b.has(item));
}

/** `_run_graph.validate_run_graph`: closure always; exact roots and tips when complete. */
export function validateRunGraph(repo: MemRepo, envelope: ObjectEnvelope): void {
  if (envelope.objectType !== "run") return;
  const payload = payloadObject(envelope);
  const status = payload.has("status") ? payload.get("status") : "running";
  if (typeof status !== "string" || !RUN_STATUSES.has(status)) {
    throw new TineError("run status is invalid", "graph.status-invalid");
  }
  const events = list(payload.get("events")) as string[];
  const eventSet = new Set(events);
  const legacy = payload.has("legacy_refs") ? payload.get("legacy_refs") : new Map();
  if (!isObject(legacy) || [...legacy.values()].some((target) => typeof target !== "string" || !eventSet.has(target))) {
    throw new TineError("legacy_refs must map names to events in the run", "graph.legacy-refs-invalid");
  }
  const complete = events.every((oid) => repo.has(oid));
  const positions = new Map(events.map((oid, index) => [oid, index]));
  const parents = new Map<string, string[]>();
  for (const eventId of events) {
    if (!repo.has(eventId)) continue;
    const event = repo.get(eventId);
    if (event.objectType !== "event") {
      throw new TineError("run events must resolve to event objects", "graph.parent-outside-graph");
    }
    const body = payloadObject(event);
    const values = list(body.get("parent_ids")) as string[];
    const causal = list(body.get("causal_ids")) as string[];
    if (values.some((parent) => !eventSet.has(parent))) {
      throw new TineError(`run event has a parent outside its event graph: ${eventId}`, "graph.parent-outside-graph");
    }
    if (causal.some((link) => !eventSet.has(link))) {
      throw new TineError(`run event has a causal link outside its event graph: ${eventId}`, "graph.causal-outside-graph");
    }
    const position = positions.get(eventId) as number;
    if ([...values, ...causal].some((link) => (positions.get(link) as number) >= position)) {
      throw new TineError("run events must be in parent-before-child/dependency order", "graph.order-not-topological");
    }
    parents.set(eventId, values);
  }
  if (!complete) return;
  const roots = new Set([...parents].filter(([, values]) => !values.length).map(([oid]) => oid));
  const referenced = new Set([...parents.values()].flat());
  const tips = new Set(events.filter((oid) => !referenced.has(oid)));
  if (!sameSet(list(payload.get("roots")), roots)) {
    throw new TineError("run roots do not match parentless events", "graph.roots-mismatch");
  }
  if (!sameSet(list(payload.get("tips")), tips)) {
    throw new TineError("run tips do not match event-graph leaves", "graph.tips-mismatch");
  }
}

// --------------------------------------------------------------------------- //
// SPEC 1.5.5: annotation chains
// --------------------------------------------------------------------------- //

/** `_annotations.validate_annotation_chain`: a new version targets what its predecessor did. */
export function validateAnnotationChain(repo: MemRepo, envelope: ObjectEnvelope): void {
  if (envelope.objectType !== "annotation") return;
  const payload = payloadObject(envelope);
  const previousId = payload.get("previous_id");
  if (!truthy(previousId)) return;
  const raw = repo.objects.get(previousId as string);
  if (raw === undefined) {
    throw new TineError(`annotation previous object is unavailable: ${String(previousId)}`, "chain.previous-unavailable");
  }
  const previous = ObjectEnvelope.decode(raw, previousId as string);
  const prior = previous.encoding === "json" ? previous.payload() : null;
  const sameTarget = isObject(prior) && prior.get("target_id") === payload.get("target_id");
  if (previous.objectType !== "annotation" || !sameTarget) {
    throw new TineError("annotation versions must target the same object", "chain.target-changed");
  }
}

// --------------------------------------------------------------------------- //
// The repository-side ops
// --------------------------------------------------------------------------- //

export interface RepoArgs {
  objects: Map<string, Uint8Array>;
  present?: string[];
  shallow?: string[];
  /** Whether the case named any of present / objects / shallow (SPEC 1.5.6 then applies). */
  checkExistence: boolean;
}

export function memRepo(args: RepoArgs): MemRepo {
  return new MemRepo(args.objects, args.present ?? [], new Set(args.shallow ?? []));
}

export function existence(args: RepoArgs): ((oid: string) => boolean) | undefined {
  if (!args.checkExistence) return undefined;
  const known = new Set([...(args.present ?? []), ...args.objects.keys(), ...(args.shallow ?? [])]);
  return (oid) => known.has(oid);
}

const sortedLinks = (links: unknown[]) => (links as string[]).slice().sort();

export function extractLinks(raw: Uint8Array, args: RepoArgs): string[] {
  return sortedLinks(validateLinks(ObjectEnvelope.decode(raw), existence(args)));
}

/** A full local read: SPEC Part 6 items 3-5 in one op. */
export function loadObject(raw: Uint8Array, expectedOid: string | null, args: RepoArgs): { oid: string; links: string[] } {
  const repo = memRepo(args);
  const envelope = ObjectEnvelope.decode(raw, expectedOid);
  const links = validateLinks(envelope, existence(args));
  validateEventMetrics(envelope);
  validateRunGraph(repo, envelope);
  validateAnnotationChain(repo, envelope);
  return { oid: envelope.oid, links: sortedLinks(links) };
}

