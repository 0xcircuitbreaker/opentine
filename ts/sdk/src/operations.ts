/**
 * Every operation of docs/api/openapi-v1.yaml: operationId -> method, path, the
 * capability that advertises it (null = core protocol) and its status.
 * tests/test_api_v1_openapi.py fails when this table and the spec differ.
 */

export interface Operation {
  readonly method: "GET" | "PUT" | "POST" | "HEAD" | "PATCH" | "DELETE";
  readonly path: string;
  readonly cap: string | null;
  readonly status: "stable" | "planned";
}

export const API_VERSION = "1.0.0";

export const OPERATIONS = {
  getCapabilities: { method: "GET", path: "/v1/capabilities", cap: null, status: "stable" },
  listRefs: { method: "GET", path: "/v1/tenants/{tenant}/refs", cap: null, status: "stable" },
  updateRef: { method: "PUT", path: "/v1/tenants/{tenant}/refs/{ref}", cap: null, status: "stable" },
  updateRefs: { method: "POST", path: "/v1/tenants/{tenant}/ref-txn", cap: "ref_txn", status: "stable" },
  negotiate: { method: "POST", path: "/v1/tenants/{tenant}/negotiate", cap: null, status: "stable" },
  fetchPack: { method: "POST", path: "/v1/tenants/{tenant}/fetch", cap: null, status: "stable" },
  uploadPack: { method: "POST", path: "/v1/tenants/{tenant}/packs", cap: null, status: "stable" },
  uploadOffset: { method: "HEAD", path: "/v1/tenants/{tenant}/packs/{upload_id}", cap: null, status: "stable" },
  uploadChunk: { method: "PATCH", path: "/v1/tenants/{tenant}/packs/{upload_id}", cap: null, status: "stable" },
  search: { method: "POST", path: "/v1/tenants/{tenant}/search", cap: null, status: "stable" },
  verifyAudit: { method: "GET", path: "/v1/tenants/{tenant}/audit/verify", cap: null, status: "stable" },
  logCheckpoint: { method: "GET", path: "/v1/tenants/{tenant}/transparency/checkpoint", cap: null, status: "stable" },
  logConsistency: { method: "GET", path: "/v1/tenants/{tenant}/transparency/consistency", cap: null, status: "stable" },
  logReceipt: { method: "GET", path: "/v1/tenants/{tenant}/transparency/receipt", cap: null, status: "stable" },
  streamEvents: { method: "GET", path: "/v1/tenants/{tenant}/events", cap: "events_sse", status: "stable" },
  listWebhooks: { method: "GET", path: "/v1/tenants/{tenant}/webhooks", cap: "webhooks", status: "stable" },
  addWebhook: { method: "POST", path: "/v1/tenants/{tenant}/webhooks", cap: "webhooks", status: "stable" },
  removeWebhook: { method: "DELETE", path: "/v1/tenants/{tenant}/webhooks/{webhook_id}", cap: "webhooks", status: "stable" },
  readObject: { method: "GET", path: "/v1/tenants/{tenant}/objects/{oid}", cap: "object_read_http", status: "planned" },
  listRuns: { method: "GET", path: "/v1/tenants/{tenant}/runs", cap: "list", status: "planned" },
  runClosure: { method: "GET", path: "/v1/tenants/{tenant}/runs/{oid}/closure", cap: "run_closure", status: "planned" },
  createShare: { method: "POST", path: "/v1/tenants/{tenant}/shares", cap: "share", status: "planned" },
  revokeShare: { method: "DELETE", path: "/v1/tenants/{tenant}/shares/{share_id}", cap: "share", status: "planned" },
  getQuota: { method: "GET", path: "/v1/tenants/{tenant}/admin/quota", cap: "admin", status: "planned" },
  getProject: { method: "GET", path: "/v1/tenants/{tenant}/project", cap: "project", status: "planned" },
  projectHistory: { method: "GET", path: "/v1/tenants/{tenant}/project/history", cap: "project", status: "planned" },
  updateProject: { method: "POST", path: "/v1/tenants/{tenant}/project", cap: "project", status: "planned" },
} as const satisfies Record<string, Operation>;

export type OperationId = keyof typeof OPERATIONS;
