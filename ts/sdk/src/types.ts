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
  social_export?: Record<string, unknown>;
  reviews?: Record<string, unknown>;
  /** 0.52: scoped API tokens (`GET|POST tokens`, `DELETE tokens/{id}`). */
  scoped_tokens?: { path?: string; access?: string[]; prefixes?: string[]; max_ttl_seconds?: number };
  /** 0.52: `GET /v1/limits`, `GET usage`, `GET /v1/auth-methods`. */
  limits?: { path?: string; usage?: string; auth_methods?: string };
  /** 0.52: only when the server trusts a CI issuer (`POST /v1/auth/oidc-exchange`). */
  oidc_exchange?: { path?: string; providers?: AuthIssuer[] };
  [key: string]: unknown;
}

/** 0.52: a metered quota; `limit` null is unlimited. */
export type QuotaMetric = "storage_bytes" | "egress_bytes" | "mirror_bytes" | "runner_minutes";

export interface Limits {
  policy: string;
  never_deletes: true;
  /** Effective defaults; a self-hosted server is unlimited unless the operator opts in. */
  defaults: Record<QuotaMetric, number | null>;
  /** The published fair-use limits of hosted use. */
  fair_use: Record<QuotaMetric, number | null>;
  windows: Record<QuotaMetric, string>;
  status: Record<QuotaMetric, 429 | 507>;
}

export interface Usage {
  tenant: string;
  usage: Record<QuotaMetric, { limit: number | null; used: number; window: string }>;
}

export interface AuthIssuer {
  name: string;
  provider: "github" | "gitlab" | "forgejo";
  issuer: string;
}

export interface AuthMethods {
  methods: Array<{ type: string; [key: string]: unknown }>;
}

export interface TokenRecord {
  id: string;
  kind: "pat" | "ci";
  tenant: string;
  access: "read" | "write";
  refs: string[];
  state: "active" | "expired" | "revoked";
  created_at: string;
  expires_at: string;
  revoked_at?: string;
  label?: string;
}

export interface MintedToken extends TokenRecord {
  /** The secret: shown once, never listed again. */
  token: string;
}

export interface IssuedToken {
  token: string;
  token_id: string;
  tenant: string;
  access: "read" | "write";
  refs: string[];
  expires_at: string;
  issued_at: string;
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

/** A cursor page of `list/runs`, `list/refs` or `log/entries` (`tine-list-page/1`). */
export interface ListPage<T> {
  items: T[];
  next_cursor: string | null;
  size?: number;
}

export interface RefEntry {
  name: string;
  oid: Oid;
}

export interface LogEntry {
  index: number;
  entry: string;
}

export interface ClosureRequest {
  haves?: Oid[];
  depth?: number | null;
  lazy_blobs?: boolean;
  pack_formats?: string[];
  pack_codecs?: string[];
}

/** A share link (`tine-share/1`); `token` only on the answer to createShare, once. */
export interface Share {
  id: string;
  run: Oid;
  scope: "read";
  created_by: string;
  created: number;
  expires: number;
  state: "active" | "expired" | "revoked";
  token?: string;
}

export interface SharedRun {
  run: Oid;
  scope: "read";
  expires: number;
}

export interface AdminStats {
  objects: Record<string, number>;
  refs: number;
  shares_active: number;
}

export interface TombstoneStored {
  stored: boolean;
  purged: boolean;
}

/** An `opentine.project` manifest version (SPEC 4.16), as its owner signed it. Verify before trusting. */
export interface ProjectManifest {
  kind: "opentine.project";
  seq: number;
  signature: Record<string, unknown>;
  [key: string]: unknown;
}

export interface Project {
  manifest: ProjectManifest;
  digest: Oid;
  seq: number;
}

export interface ProjectHistory {
  versions: ProjectManifest[];
  next_cursor: number | null;
  total: number;
}

export interface SocialCounts {
  stars: number;
  watches: number;
}

/** An `opentine.review` version (SPEC 4.20), as its reviewer signed it. Verify before trusting. */
export interface ReviewVersion {
  kind: "opentine.review";
  seq: number;
  signature: Record<string, unknown>;
  [key: string]: unknown;
}

/** An `opentine.review-gate` decision (SPEC 4.20), as its reviewer signed it. */
export interface ReviewGate {
  kind: "opentine.review-gate";
  review: Oid;
  signature: Record<string, unknown>;
  [key: string]: unknown;
}

/** A Review whole: what `tine review export` writes and `verifyReviewBundle` checks. */
export interface ReviewBundle {
  kind: "opentine.review-bundle";
  bundle_version: 1;
  versions: ReviewVersion[];
  decisions: ReviewGate[];
}

export interface Review {
  bundle: ReviewBundle;
  head: Oid;
  seq: number;
}

export interface ReviewSummary {
  review_id: string;
  seq: number;
  head: Oid;
}

export interface ReviewDecided {
  stored: boolean;
  digest: Oid;
}

/** An `opentine-coord/1` task (`caps.coord`, SPEC 8.22); leases run on the server's clock. */
export interface Task {
  task: string;
  title: string;
  status: "open" | "claimed" | "done";
  holder: string | null;
  fencing: number;
  lease_expires_ms: number | null;
  updated_ms: number;
}

// 0.52 admin surface (tag admin, SPEC 8.27). None of these carries signed data.

export type Role = "reader" | "writer" | "admin";

export interface Tenant {
  name: string;
  display_name: string;
  archived: boolean;
  /** null for a tenant only a bearer token names (not registered on the admin surface). */
  created_at: number | null;
  role: Role | null;
}

export interface Session {
  subject: string;
  /** `session:passkey`, `session:dev` or `bearer`. */
  method: string;
  expires_at: number | null;
  tenants: Tenant[];
}

/** A new session; `token` is a bearer secret (`tine_sess_...`) shown once. */
export interface SessionOpened {
  token: string;
  subject: string;
  method: string;
  expires_at: number;
}

export interface Member {
  subject: string;
  role: Role;
}

export interface Invitation {
  id: string;
  tenant: string;
  role: Role;
  invited_by: string;
  expires_at: number;
}

/** The answer to createInvitation: the single-use `token` is shown only here. */
export interface InvitationCreated extends Invitation {
  token: string;
}

export interface TenantSettings {
  settings: { description?: string; homepage?: string; default_ref?: string };
  /** Published fair-use limits; exceeding one is a 429, and nothing is deleted. */
  limits: Record<string, number>;
}

export interface RetentionPolicy {
  keep_days: number;
  refs?: Record<string, number>;
  status?: Record<string, number>;
  tier?: Record<string, number>;
}

export interface Retention {
  policy: RetentionPolicy | null;
  /** Always false: the server stores the policy and never deletes on its own. */
  server_deletes: false;
}

export interface Hold {
  oid: Oid;
  target: string;
}

/** WebAuthn JSON (binary fields base64url) as `navigator.credentials` takes and returns it. */
export type PasskeyOptions = Record<string, unknown> & { challenge: string };

export interface PasskeyRegistration {
  challenge: string;
  clientDataJSON: string;
  attestationObject: string;
  transports?: string[];
  invitation?: string;
}

export interface PasskeyAssertion {
  challenge: string;
  credential_id: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string | null;
}

export interface PasskeyRegistered {
  credential_id: string;
  subject: string;
  alg: -7 | -8;
  tenant?: Tenant;
  session?: SessionOpened;
}
