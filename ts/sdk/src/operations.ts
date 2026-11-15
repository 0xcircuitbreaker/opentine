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
  readObject: { method: "GET", path: "/v1/tenants/{tenant}/objects/{oid}", cap: "object_read_http", status: "stable" },
  runClosure: { method: "POST", path: "/v1/tenants/{tenant}/runs/{oid}/closure", cap: "run_closure", status: "stable" },
  listRuns: { method: "GET", path: "/v1/tenants/{tenant}/list/runs", cap: "list", status: "stable" },
  listRefPage: { method: "GET", path: "/v1/tenants/{tenant}/list/refs", cap: "list", status: "stable" },
  logEntries: { method: "GET", path: "/v1/tenants/{tenant}/log/entries", cap: "log_http", status: "stable" },
  adminStats: { method: "GET", path: "/v1/tenants/{tenant}/admin/stats", cap: "admin", status: "stable" },
  listShares: { method: "GET", path: "/v1/tenants/{tenant}/shares", cap: "share", status: "stable" },
  createShare: { method: "POST", path: "/v1/tenants/{tenant}/shares", cap: "share", status: "stable" },
  revokeShare: { method: "DELETE", path: "/v1/tenants/{tenant}/shares/{share_id}", cap: "share", status: "stable" },
  getSharedRun: { method: "GET", path: "/v1/share/{token}", cap: "share", status: "stable" },
  sharedClosure: { method: "POST", path: "/v1/share/{token}/closure", cap: "share", status: "stable" },
  readSharedObject: { method: "GET", path: "/v1/share/{token}/objects/{oid}", cap: "share", status: "stable" },
  getTombstone: { method: "GET", path: "/v1/tenants/{tenant}/tombstones/{oid}", cap: "tombstones", status: "stable" },
  putTombstone: { method: "PUT", path: "/v1/tenants/{tenant}/tombstones/{oid}", cap: "tombstones", status: "stable" },
  getProject: { method: "GET", path: "/v1/tenants/{tenant}/project", cap: "project", status: "stable" },
  projectHistory: { method: "GET", path: "/v1/tenants/{tenant}/project/history", cap: "project", status: "stable" },
  updateProject: { method: "PUT", path: "/v1/tenants/{tenant}/project", cap: "project", status: "stable" },
  socialCounts: { method: "GET", path: "/v1/tenants/{tenant}/social", cap: "social_export", status: "stable" },
  listReviews: { method: "GET", path: "/v1/tenants/{tenant}/reviews", cap: "reviews", status: "stable" },
  getReview: { method: "GET", path: "/v1/tenants/{tenant}/reviews/{review_id}", cap: "reviews", status: "stable" },
  updateReview: { method: "PUT", path: "/v1/tenants/{tenant}/reviews/{review_id}", cap: "reviews", status: "stable" },
  decideReviewGate: { method: "POST", path: "/v1/tenants/{tenant}/reviews/{review_id}/decisions", cap: "reviews", status: "stable" },
  listTasks: { method: "GET", path: "/v1/tenants/{tenant}/coord/tasks", cap: "coord", status: "stable" },
  addTask: { method: "POST", path: "/v1/tenants/{tenant}/coord/tasks", cap: "coord", status: "stable" },
  getTask: { method: "GET", path: "/v1/tenants/{tenant}/coord/tasks/{task}", cap: "coord", status: "stable" },
  claimTask: { method: "POST", path: "/v1/tenants/{tenant}/coord/tasks/{task}/claim", cap: "coord", status: "stable" },
  heartbeatTask: { method: "POST", path: "/v1/tenants/{tenant}/coord/tasks/{task}/heartbeat", cap: "coord", status: "stable" },
  finishTask: { method: "POST", path: "/v1/tenants/{tenant}/coord/tasks/{task}/done", cap: "coord", status: "stable" },
  // 0.52 admin surface (tag admin, SPEC 8.27): session, login, tenants -- no signed data.
  getSession: { method: "GET", path: "/v1/session", cap: "session", status: "stable" },
  endSession: { method: "DELETE", path: "/v1/session", cap: "session", status: "stable" },
  devLogin: { method: "POST", path: "/v1/auth/dev/login", cap: "session", status: "stable" },
  passkeyRegistrationOptions: { method: "POST", path: "/v1/auth/passkey/registration/options", cap: "session", status: "stable" },
  registerPasskey: { method: "POST", path: "/v1/auth/passkey/registration", cap: "session", status: "stable" },
  passkeyAssertionOptions: { method: "POST", path: "/v1/auth/passkey/assertion/options", cap: "session", status: "stable" },
  passkeyLogin: { method: "POST", path: "/v1/auth/passkey/assertion", cap: "session", status: "stable" },
  listTenants: { method: "GET", path: "/v1/tenants", cap: "tenancy", status: "stable" },
  createTenant: { method: "POST", path: "/v1/tenants", cap: "tenancy", status: "stable" },
  acceptInvitation: { method: "POST", path: "/v1/invitations/accept", cap: "tenancy", status: "stable" },
  getTenant: { method: "GET", path: "/v1/tenants/{tenant}", cap: "tenancy", status: "stable" },
  renameTenant: { method: "PATCH", path: "/v1/tenants/{tenant}", cap: "tenancy", status: "stable" },
  archiveTenant: { method: "POST", path: "/v1/tenants/{tenant}/archive", cap: "tenancy", status: "stable" },
  unarchiveTenant: { method: "POST", path: "/v1/tenants/{tenant}/unarchive", cap: "tenancy", status: "stable" },
  listMembers: { method: "GET", path: "/v1/tenants/{tenant}/members", cap: "tenancy", status: "stable" },
  setMember: { method: "PUT", path: "/v1/tenants/{tenant}/members/{subject}", cap: "tenancy", status: "stable" },
  removeMember: { method: "DELETE", path: "/v1/tenants/{tenant}/members/{subject}", cap: "tenancy", status: "stable" },
  listInvitations: { method: "GET", path: "/v1/tenants/{tenant}/invitations", cap: "tenancy", status: "stable" },
  createInvitation: { method: "POST", path: "/v1/tenants/{tenant}/invitations", cap: "tenancy", status: "stable" },
  revokeInvitation: { method: "DELETE", path: "/v1/tenants/{tenant}/invitations/{invitation_id}", cap: "tenancy", status: "stable" },
  getSettings: { method: "GET", path: "/v1/tenants/{tenant}/settings", cap: "tenancy", status: "stable" },
  updateSettings: { method: "PATCH", path: "/v1/tenants/{tenant}/settings", cap: "tenancy", status: "stable" },
  getRetention: { method: "GET", path: "/v1/tenants/{tenant}/retention", cap: "tenancy", status: "stable" },
  setRetention: { method: "PUT", path: "/v1/tenants/{tenant}/retention", cap: "tenancy", status: "stable" },
  listHolds: { method: "GET", path: "/v1/tenants/{tenant}/holds", cap: "tenancy", status: "stable" },
  addHold: { method: "POST", path: "/v1/tenants/{tenant}/holds", cap: "tenancy", status: "stable" },
  releaseHold: { method: "DELETE", path: "/v1/tenants/{tenant}/holds/{oid}", cap: "tenancy", status: "stable" },
} as const satisfies Record<string, Operation>;

export type OperationId = keyof typeof OPERATIONS;
