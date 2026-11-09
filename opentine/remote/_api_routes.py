"""The ``tine serve`` HTTP API v1 route table (0.46): the source of ``docs/api/openapi-v1.yaml``.

Every route :class:`opentine.remote.app.RemoteApp` dispatches is listed here,
with the capability key that advertises it in ``GET /v1/capabilities``
(``None`` for the core protocol) and its status: ``stable`` routes are served
by this build; ``planned`` routes (none since 0.46.1) are reserved shapes the
hosted web app needs and are served only once their capability is advertised.
``tests/test_api_v1_openapi.py`` probes the live app with every entry, so the
table, the spec and the dispatcher cannot drift apart.

Rules every v1 implementation (``tine serve`` and the hosted service) keeps:
tenant routes are private by default (no anonymous read), every read is
authorized per tenant, an object the caller may not read answers exactly like
one that does not exist (a uniform ``404``, no oid-existence oracle), and the
server never signs anything as a user: signed objects arrive client-signed.
"""

from __future__ import annotations

from typing import NamedTuple

API_VERSION = "1.0.0"
PACK = "application/vnd.opentine.pack"
OBJECT = "application/vnd.opentine.object"
SSE = "text/event-stream"


class Route(NamedTuple):
    method: str
    path: str  # under ``/v1``; ``{tenant}`` etc. are path parameters
    operation: str
    summary: str
    cap: str | None  # capability key in GET /v1/capabilities; None = core protocol
    status: str  # "stable" | "planned"
    permission: str | None  # the authorization action; None = unauthenticated
    request: str | None  # component schema name, a media type, or None
    responses: tuple[tuple[str, str], ...]  # (status code, schema name or media type)


T = "/tenants/{tenant}"
_ERR = (("401", "Error"), ("403", "Error"), ("404", "Error"), ("429", "Error"))
_PUBLIC = (("404", "Error"), ("429", "Error"))  # no bearer: unknown, expired, revoked alike

ROUTES: tuple[Route, ...] = (
    Route("GET", "/capabilities", "getCapabilities", "What this server speaks",
          None, "stable", None, None, (("200", "Capabilities"),)),
    Route("GET", T + "/refs", "listRefs", "Every ref of the tenant",
          None, "stable", "read_ref", None, (("200", "RefList"), *_ERR)),
    Route("PUT", T + "/refs/{ref}", "updateRef", "Compare-and-swap one ref",
          None, "stable", "update_ref", "RefUpdate",
          (("200", "Updated"), ("409", "Updated"), ("400", "Error"), *_ERR)),
    Route("POST", T + "/ref-txn", "updateRefs", "All-or-nothing ref transaction",
          "ref_txn", "stable", "update_ref", "RefTxn",
          (("200", "Updated"), ("409", "Updated"), ("400", "Error"), *_ERR)),
    Route("POST", T + "/negotiate", "negotiate", "Which wanted objects the client lacks",
          None, "stable", "negotiate", "Negotiate", (("200", "Missing"), ("400", "Error"), *_ERR)),
    Route("POST", T + "/fetch", "fetchPack", "A pack of the wanted closure",
          None, "stable", "fetch", "Fetch",
          (("200", PACK), ("400", "Error"), ("503", "Error"), *_ERR)),
    Route("POST", T + "/packs", "uploadPack", "Install a pack, or declare a resumable upload",
          None, "stable", "upload", "UploadDeclaration",
          (("201", "Installed"), ("400", "Error"), ("503", "Error"), *_ERR)),
    Route("HEAD", T + "/packs/{upload_id}", "uploadOffset", "A resumable upload's offset",
          None, "stable", "upload", None, (("200", "Offset"), *_ERR)),
    Route("PATCH", T + "/packs/{upload_id}", "uploadChunk", "Append to a resumable upload",
          None, "stable", "upload", "application/offset+octet-stream",
          (("200", "Offset"), ("201", "Installed"), ("409", "Offset"), ("400", "Error"), *_ERR)),
    Route("POST", T + "/search", "search", "Object ids matching an index query",
          None, "stable", "search", "SearchQuery",
          (("200", "SearchResult"), ("400", "Error"), *_ERR)),
    Route("GET", T + "/audit/verify", "verifyAudit", "The server-keyed audit chain status",
          None, "stable", "audit", None, (("200", "AuditStatus"), *_ERR)),
    Route("GET", T + "/transparency/checkpoint", "logCheckpoint", "The signed log checkpoint",
          None, "stable", "read_ref", None, (("200", "Checkpoint"), *_ERR)),
    Route("GET", T + "/transparency/consistency", "logConsistency", "A consistency proof",
          None, "stable", "read_ref", None, (("200", "Consistency"), *_ERR)),
    Route("GET", T + "/transparency/receipt", "logReceipt", "An inclusion receipt for a ref move",
          None, "stable", "read_ref", None, (("200", "Receipt"), *_ERR)),
    Route("GET", T + "/events", "streamEvents", "tine-event/1 Server-Sent Events",
          "events_sse", "stable", "read_ref", None, (("200", SSE), ("503", "Error"), *_ERR)),
    Route("GET", T + "/webhooks", "listWebhooks", "Webhooks and recent deliveries",
          "webhooks", "stable", "webhooks", None, (("200", "WebhookList"), *_ERR)),
    Route("POST", T + "/webhooks", "addWebhook", "Register a signed webhook",
          "webhooks", "stable", "webhooks", "WebhookRequest",
          (("201", "Webhook"), ("400", "Error"), *_ERR)),
    Route("DELETE", T + "/webhooks/{webhook_id}", "removeWebhook", "Remove a webhook",
          "webhooks", "stable", "webhooks", None, (("200", "Removed"), *_ERR)),
    # 0.46 hosted-beta caps (SPEC 8.14) for opentine-web M2/M3. A refusal on these
    # is the uniform 404, also for another tenant's caller.
    Route("GET", T + "/objects/{oid}", "readObject", "One stored object envelope",
          "object_read_http", "stable", "fetch", None, (("200", OBJECT), ("304", OBJECT), *_ERR)),
    Route("POST", T + "/runs/{oid}/closure", "runClosure", "A pack of one run's closure",
          "run_closure", "stable", "fetch", "Closure", (("200", PACK), ("400", "Error"), *_ERR)),
    Route("GET", T + "/list/runs", "listRuns", "Run oids of the tenant in oid order, paged",
          "list", "stable", "read_ref", None, (("200", "ListPage"), ("400", "Error"), *_ERR)),
    Route("GET", T + "/list/refs", "listRefPage", "Refs of the tenant in name order, paged",
          "list", "stable", "read_ref", None, (("200", "ListPage"), ("400", "Error"), *_ERR)),
    Route("GET", T + "/log/entries", "logEntries", "The tenant's transparency-log entries",
          "log_http", "stable", "read_ref", None, (("200", "ListPage"), ("400", "Error"), *_ERR)),
    Route("GET", T + "/admin/stats", "adminStats", "Objects by type, refs and active shares",
          "admin", "stable", "admin", None, (("200", "AdminStats"), *_ERR)),
    Route("GET", T + "/shares", "listShares", "The tenant's share links (never a token)",
          "share", "stable", "share", None, (("200", "ShareList"), *_ERR)),
    Route("POST", T + "/shares", "createShare", "A read-only capability link to one run",
          "share", "stable", "share", "ShareRequest", (("201", "Share"), ("400", "Error"), *_ERR)),
    Route("DELETE", T + "/shares/{share_id}", "revokeShare", "Revoke a share link",
          "share", "stable", "share", None, (("200", "Share"), *_ERR)),
    Route("GET", "/share/{token}", "getSharedRun", "The run a share token reads",
          "share", "stable", None, None, (("200", "SharedRun"), *_PUBLIC)),
    Route("POST", "/share/{token}/closure", "sharedClosure", "A pack of the shared run's closure",
          "share", "stable", None, "Closure", (("200", PACK), *_PUBLIC)),
    Route("GET", "/share/{token}/objects/{oid}", "readSharedObject", "One object of the closure",
          "share", "stable", None, None, (("200", OBJECT), ("304", OBJECT), *_PUBLIC)),
    Route("GET", T + "/tombstones/{oid}", "getTombstone", "The signed tombstone of a purged blob",
          "tombstones", "stable", "fetch", None, (("200", "TombstoneReply"), *_ERR)),
    Route("PUT", T + "/tombstones/{oid}", "putTombstone",
          "Store a client-signed tombstone; for a held blob, purge it (admin)",
          "tombstones", "stable", "upload", "Tombstone",
          (("201", "TombstoneStored"), ("400", "Error"), *_ERR)),
    # 0.46.1 projects (ROADMAP §11): the manifest only; tine serve stores no code.
    Route("GET", T + "/project", "getProject", "The current opentine.project manifest",
          "project", "stable", "read_ref", None, (("200", "Project"), *_ERR)),
    Route("GET", T + "/project/history", "projectHistory", "Manifest versions, oldest first, paged",
          "project", "stable", "read_ref", None,
          (("200", "ProjectHistory"), ("400", "Error"), *_ERR)),
    Route("PUT", T + "/project", "updateProject", "CAS project/manifest to a client-signed version",
          "project", "stable", "update_ref", "ProjectUpdate",
          (("200", "ProjectUpdated"), ("409", "ProjectUpdated"), ("400", "Error"), *_ERR)),
    Route("GET", T + "/social", "socialCounts", "Count-only stars and watches (self-host parity)",
          "social_export", "stable", "read_ref", None, (("200", "SocialCounts"), *_ERR)),
    # 0.47 Reviews (SPEC 4.19, 8.19): stored as their reviewers signed them.
    Route("GET", T + "/reviews", "listReviews", "Every Review of the tenant, with its head",
          "reviews", "stable", "read_ref", None, (("200", "ReviewList"), *_ERR)),
    Route("GET", T + "/reviews/{review_id}", "getReview", "A Review as a verifiable bundle",
          "reviews", "stable", "read_ref", None, (("200", "Review"), *_ERR)),
    Route("PUT", T + "/reviews/{review_id}", "updateReview",
          "CAS a Review to its next client-signed version", "reviews", "stable", "update_ref",
          "ReviewUpdate",
          (("200", "ReviewUpdated"), ("409", "ReviewUpdated"), ("400", "Error"), *_ERR)),
    Route("POST", T + "/reviews/{review_id}/decisions", "decideReviewGate",
          "Store a client-signed gate decision", "reviews", "stable", "update_ref",
          "ReviewDecision", (("201", "ReviewDecided"), ("400", "Error"), *_ERR)),
    # 0.47 remote task backend (SPEC 8.19): opentine-coord/1 leases on the server's clock.
    Route("GET", T + "/coord/tasks", "listTasks", "Every coordination task of the tenant",
          "coord", "stable", "read_ref", None, (("200", "TaskList"), *_ERR)),
    Route("POST", T + "/coord/tasks", "addTask", "Create an open task",
          "coord", "stable", "update_ref", "TaskAdd",
          (("201", "TaskReply"), ("409", "LeaseRefusal"), ("400", "Error"), *_ERR)),
    Route("GET", T + "/coord/tasks/{task}", "getTask", "One task and its lease",
          "coord", "stable", "read_ref", None, (("200", "TaskReply"), *_ERR)),
    *(Route("POST", T + "/coord/tasks/{task}/" + action, op, text, "coord", "stable",
            "update_ref", "TaskLease",
            (("200", "TaskReply"), ("409", "LeaseRefusal"), ("400", "Error"), *_ERR))
      for action, op, text in (
          ("claim", "claimTask", "Take the lease by compare-and-swap; returns the fencing token"),
          ("heartbeat", "heartbeatTask", "Extend the lease (holder and current fencing token)"),
          ("done", "finishTask", "Close the task (holder and current fencing token)"))),
)  # fmt: skip


def stable() -> tuple[Route, ...]:
    return tuple(route for route in ROUTES if route.status == "stable")


__all__ = ["API_VERSION", "OBJECT", "PACK", "ROUTES", "Route", "SSE", "stable"]
