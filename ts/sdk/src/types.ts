/** Request and response bodies of docs/api/openapi-v1.yaml (components/schemas). */

/** A typed object id: `TYPE:sha256:HEX`. */
export type Oid = string;

export interface ErrorBody {
  error: string;
}

export interface Capabilities {
  protocol: "opentine-remote/1";
  object_format: string;
  pack_format: string;
  pack_formats: string[];
  roles: string[];
  version: string;
  authentication?: string[];
  ref_txn?: boolean;
  resumable_upload?: boolean;
  events_sse?: { path?: string; [key: string]: unknown };
  webhooks?: { format?: string; keys?: Record<string, string>; replay_window?: number; [key: string]: unknown };
  object_read_http?: Record<string, unknown>;
  run_closure?: Record<string, unknown>;
  list?: Record<string, unknown>;
  share?: Record<string, unknown>;
  admin?: Record<string, unknown>;
  project?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface RefList {
  refs: Record<string, Oid>;
}

export interface RefUpdate {
  new: Oid;
  expected_old?: Oid | null;
  force?: boolean;
}

export interface RefTxnUpdate {
  name: string;
  new: Oid;
  expected_old?: Oid | null;
}

export interface Updated {
  updated: boolean;
}

export interface FetchRequest {
  wants: Oid[];
  haves?: Oid[];
  depth?: number | null;
  object_types?: string[];
  pack_formats?: string[];
  pack_codecs?: string[];
}

export interface Installed {
  objects?: number;
  pack_id?: string;
  offset?: number;
  upload_id?: string;
}

export interface SearchResult {
  objects: Oid[];
  truncated: boolean;
}

export interface AuditStatus {
  ok: boolean;
  status: string;
  warnings: unknown[];
}

export interface Checkpoint {
  checkpoint: string;
  size: number;
  vkey: string;
}

export interface Webhook {
  id: string;
  url: string;
  kinds: string[];
  created: string;
}

export interface WebhookList {
  webhooks: Webhook[];
  recent: unknown[];
}

export interface RunPage {
  runs: { oid: Oid; [key: string]: unknown }[];
  next_cursor?: string | null;
}

export interface Share {
  id: string;
  run: Oid;
  url: string;
  expires_at?: string;
}

export interface Quota {
  limits: Record<string, unknown>;
  usage: Record<string, unknown>;
}
