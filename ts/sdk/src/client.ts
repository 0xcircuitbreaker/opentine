/**
 * A typed client for the OpenTine remote API v1 (docs/api/openapi-v1.yaml).
 * It needs nothing but `fetch`. Bytes it fetches are not trusted here: use
 * `@opentine/sdk/verified`, which checks them with the TS verifier.
 */

import { OPERATIONS, type OperationId } from "./operations.js";
import type {
  AdminStats,
  AuditStatus,
  Capabilities,
  Checkpoint,
  ClosureRequest,
  FetchRequest,
  Installed,
  Oid,
  ListPage,
  LogEntry,
  RefEntry,
  RefList,
  RefTxnUpdate,
  RefUpdate,
  SearchResult,
  Share,
  SharedRun,
  TombstoneStored,
  Webhook,
  WebhookList,
} from "./types.js";

export const PACK_TYPE = "application/vnd.opentine.pack";

export interface ClientOptions {
  /** The remote's base URL, e.g. `https://tine.example`. */
  baseUrl: string;
  tenant: string;
  /** Bearer token (static token or OIDC JWT). Tenant routes are private without one. */
  token?: string;
  fetch?: typeof fetch;
}

/** A non-2xx answer. A 404 is uniform: it does not say whether the thing exists. */
export class TineApiError extends Error {
  constructor(
    readonly status: number,
    readonly body: unknown,
    readonly retryAfter: number | null,
  ) {
    const reason = typeof body === "object" && body !== null && "error" in body ? String(body.error) : "";
    super(`HTTP ${status}${reason ? `: ${reason}` : ""}`);
    this.name = "TineApiError";
  }
}

type Params = Record<string, string>;

/** Retry-After in seconds: delta-seconds or an HTTP-date; null when absent or unparseable. */
export function retryAfter(value: string | null, now: number = Date.now()): number | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  const date = Date.parse(trimmed);
  return Number.isNaN(date) ? null : Math.max(0, Math.ceil((date - now) / 1000));
}

function page(cursor?: string, limit?: number): Params {
  const query: Params = {};
  if (cursor) query.cursor = cursor;
  if (limit !== undefined) query.limit = String(limit);
  return query;
}

export class TineClient {
  readonly baseUrl: string;
  readonly tenant: string;
  private readonly token?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.tenant = options.tenant;
    this.token = options.token;
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** The URL of an operation, every path parameter percent-encoded. */
  url(operation: OperationId, params: Params = {}, query: Params = {}): string {
    const values: Params = { tenant: this.tenant, ...params };
    const path = OPERATIONS[operation].path.replace(/\{([a-z_]+)\}/g, (_, name: string) => {
      const value = values[name];
      if (value === undefined || value === "") throw new TypeError(`missing path parameter ${name}`);
      // "." and ".." would be dot segments the URL parser collapses, retargeting the request.
      if (value === "." || value === "..") throw new TypeError(`invalid path parameter ${name}`);
      return encodeURIComponent(value);
    });
    const search = new URLSearchParams(query).toString();
    return this.baseUrl + path + (search ? `?${search}` : "");
  }

  /** Send one operation; `ok` lists the statuses that are answers rather than errors. */
  async send(
    operation: OperationId,
    init: {
      params?: Params;
      query?: Params;
      json?: unknown;
      body?: Uint8Array;
      headers?: Params;
      ok?: number[];
      anonymous?: boolean;
    } = {},
  ): Promise<Response> {
    const headers: Params = { ...(init.headers ?? {}) };
    if (this.token && !init.anonymous) headers.authorization = `Bearer ${this.token}`;
    let body: BodyInit | undefined;
    if (init.json !== undefined) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(init.json);
    } else if (init.body !== undefined) {
      body = init.body as unknown as BodyInit;
    }
    const response = await this.fetchImpl(this.url(operation, init.params, init.query), {
      method: OPERATIONS[operation].method,
      headers,
      body,
      // Never follow a redirect: it would carry the bearer token to wherever it points.
      redirect: "error",
    });
    const ok = init.ok ?? [];
    if (response.ok || ok.includes(response.status)) return response;
    let parsed: unknown = null;
    try {
      parsed = await response.json();
    } catch {
      parsed = null;
    }
    throw new TineApiError(response.status, parsed, retryAfter(response.headers.get("retry-after")));
  }

  private async json<T>(operation: OperationId, init: Parameters<TineClient["send"]>[1] = {}): Promise<T> {
    return (await (await this.send(operation, init)).json()) as T;
  }

  private async bytes(operation: OperationId, init: Parameters<TineClient["send"]>[1] = {}): Promise<Uint8Array> {
    return new Uint8Array(await (await this.send(operation, init)).arrayBuffer());
  }

  private async cas(operation: OperationId, init: Parameters<TineClient["send"]>[1]): Promise<boolean> {
    const response = await this.send(operation, { ...init, ok: [409] });
    return ((await response.json()) as { updated: boolean }).updated === true;
  }

  capabilities(): Promise<Capabilities> {
    return this.json("getCapabilities");
  }

  async listRefs(): Promise<Record<string, Oid>> {
    return (await this.json<RefList>("listRefs")).refs;
  }

  /** Compare-and-swap one ref; false when `expected_old` no longer holds (409). */
  updateRef(name: string, update: RefUpdate): Promise<boolean> {
    return this.cas("updateRef", { params: { ref: name }, json: update });
  }

  /** All-or-nothing (`caps.ref_txn`); false when any precondition fails (409). */
  updateRefs(updates: RefTxnUpdate[], force = false): Promise<boolean> {
    return this.cas("updateRefs", { json: force ? { updates, force } : { updates } });
  }

  async negotiate(wants: Oid[], haves: Oid[] = [], depth?: number): Promise<Oid[]> {
    const json = depth === undefined ? { wants, haves } : { wants, haves, depth };
    return (await this.json<{ missing: Oid[] }>("negotiate", { json })).missing;
  }

  /** The raw pack for `wants` (unverified; see `fetchVerified`). */
  fetchPack(request: FetchRequest): Promise<Uint8Array> {
    return this.bytes("fetchPack", { json: request });
  }

  uploadPack(pack: Uint8Array): Promise<Installed> {
    return this.json("uploadPack", { body: pack, headers: { "content-type": PACK_TYPE } });
  }

  search(query: Record<string, unknown>): Promise<SearchResult> {
    return this.json("search", { json: query });
  }

  verifyAudit(): Promise<AuditStatus> {
    return this.json("verifyAudit");
  }

  logCheckpoint(): Promise<Checkpoint> {
    return this.json("logCheckpoint");
  }

  listWebhooks(): Promise<WebhookList> {
    return this.json("listWebhooks");
  }

  addWebhook(url: string, kinds?: string[]): Promise<Webhook> {
    return this.json("addWebhook", { json: kinds ? { url, kinds } : { url } });
  }

  async removeWebhook(id: string): Promise<void> {
    await this.send("removeWebhook", { params: { webhook_id: id } });
  }

  /** One stored envelope (`caps.object_read_http`; unverified, see `readObjectVerified`). */
  readObject(oid: Oid): Promise<Uint8Array> {
    return this.bytes("readObject", { params: { oid } });
  }

  /** Run oids, paged (`caps.list`). */
  listRuns(cursor?: string, limit?: number): Promise<ListPage<Oid>> {
    return this.json("listRuns", { query: page(cursor, limit) });
  }

  /** Refs in name order, paged (`caps.list`). */
  listRefPage(cursor?: string, limit?: number): Promise<ListPage<RefEntry>> {
    return this.json("listRefPage", { query: page(cursor, limit) });
  }

  /** This tenant's transparency-log entries, paged (`caps.log_http`). */
  logEntries(cursor?: string, limit?: number): Promise<ListPage<LogEntry>> {
    return this.json("logEntries", { query: page(cursor, limit) });
  }

  /** A pack of one run's closure (`caps.run_closure`; unverified). */
  runClosure(oid: Oid, request: ClosureRequest = {}): Promise<Uint8Array> {
    return this.bytes("runClosure", { params: { oid }, json: request });
  }

  /** A read-only link to one run (`caps.share`); the answer carries the token once. */
  createShare(run: Oid, ttl?: number): Promise<Share> {
    return this.json("createShare", { json: ttl ? { run, ttl } : { run } });
  }

  async listShares(run?: Oid): Promise<Share[]> {
    return (await this.json<{ shares: Share[] }>("listShares", { query: run ? { run } : {} })).shares;
  }

  revokeShare(id: string): Promise<Share> {
    return this.json("revokeShare", { params: { share_id: id } });
  }

  /** The run a share token reads (no bearer is sent, whatever the client holds). */
  sharedRun(token: string): Promise<SharedRun> {
    return this.json("getSharedRun", { params: { token }, anonymous: true });
  }

  sharedClosure(token: string, request: ClosureRequest = {}): Promise<Uint8Array> {
    return this.bytes("sharedClosure", { params: { token }, json: request, anonymous: true });
  }

  readSharedObject(token: string, oid: Oid): Promise<Uint8Array> {
    return this.bytes("readSharedObject", { params: { token, oid }, anonymous: true });
  }

  adminStats(): Promise<AdminStats> {
    return this.json("adminStats");
  }

  /** The signed tombstone of a purged blob (`caps.tombstones`); verify it before trusting it. */
  async getTombstone(oid: Oid): Promise<Record<string, unknown>> {
    return (await this.json<{ tombstone: Record<string, unknown> }>("getTombstone", { params: { oid } })).tombstone;
  }

  putTombstone(oid: Oid, tombstone: Record<string, unknown>): Promise<TombstoneStored> {
    return this.json("putTombstone", { params: { oid }, json: tombstone });
  }

  /** `tine-event/1` events until the server closes the stream or `signal` aborts. */
  async *events(lastEventId?: string, signal?: AbortSignal): AsyncGenerator<{ id: string; kind: string; data: unknown }> {
    const headers: Params = lastEventId ? { "last-event-id": lastEventId } : {};
    if (this.token) headers.authorization = `Bearer ${this.token}`;
    const response = await this.fetchImpl(this.url("streamEvents"), { headers, signal, redirect: "error" });
    if (!response.ok || response.body === null) {
      let parsed: unknown = null;
      try {
        parsed = await response.json();
      } catch {
        parsed = null;
      }
      throw new TineApiError(response.status, parsed, retryAfter(response.headers.get("retry-after")));
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffered = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      buffered += decoder.decode(value, { stream: true }).replace(/\r\n?/g, "\n");
      let end: number;
      while ((end = buffered.indexOf("\n\n")) >= 0) {
        const frame = buffered.slice(0, end);
        buffered = buffered.slice(end + 2);
        const fields: Params = {};
        for (const line of frame.split("\n")) {
          if (line.startsWith(":")) continue;
          const colon = line.indexOf(":");
          if (colon <= 0) continue;
          const key = line.slice(0, colon);
          const field = line.slice(colon + 1).replace(/^ /, "");
          // Per the SSE spec, repeated data lines join with a newline.
          fields[key] = key === "data" && fields.data !== undefined ? `${fields.data}\n${field}` : field;
        }
        if (fields.data !== undefined && fields.event !== undefined) {
          yield { id: fields.id ?? "", kind: fields.event, data: JSON.parse(fields.data) };
        }
      }
    }
  }
}
