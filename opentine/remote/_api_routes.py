"""The ``tine serve`` HTTP API v1 route table (0.46): the source of ``docs/api/openapi-v1.yaml``.

Every route :class:`opentine.remote.app.RemoteApp` dispatches is listed here,
with the capability key that advertises it in ``GET /v1/capabilities``
(``None`` for the core protocol) and its status: ``stable`` routes are served
by this build; ``planned`` routes are reserved for the 0.46 ``caps`` the
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
    # 0.46 caps for opentine-web M2/M3 (ROADMAP 0.46.0, §11). Reserved here so the
    # hosted service and tine serve converge on one shape.
    Route("GET", T + "/objects/{oid}", "readObject", "One stored object envelope",
          "object_read_http", "planned", "fetch", None, (("200", OBJECT), *_ERR)),
    Route("GET", T + "/runs", "listRuns", "Runs of the tenant, newest first, paged",
          "list", "planned", "read_ref", None, (("200", "RunPage"), ("400", "Error"), *_ERR)),
    Route("GET", T + "/runs/{oid}/closure", "runClosure", "A pack of one run's closure",
          "run_closure", "planned", "fetch", None, (("200", PACK), *_ERR)),
    Route("POST", T + "/shares", "createShare", "A capability link to one run",
          "share", "planned", "share", "ShareRequest", (("201", "Share"), ("400", "Error"), *_ERR)),
    Route("DELETE", T + "/shares/{share_id}", "revokeShare", "Revoke a share link",
          "share", "planned", "share", None, (("200", "Removed"), *_ERR)),
    Route("GET", T + "/admin/quota", "getQuota", "The tenant's quota and usage",
          "admin", "planned", "admin", None, (("200", "Quota"), *_ERR)),
    Route("GET", T + "/project", "getProject", "The opentine-project/1 manifest",
          "project", "planned", "read_ref", None, (("200", OBJECT), *_ERR)),
    Route("GET", T + "/project/history", "projectHistory", "Every logged manifest version",
          "project", "planned", "read_ref", None, (("200", "ProjectHistory"), *_ERR)),
    Route("POST", T + "/project", "updateProject", "CAS project/manifest to a client-signed one",
          "project", "planned", "update_ref", "ProjectUpdate",
          (("200", "Updated"), ("409", "Updated"), ("400", "Error"), *_ERR)),
)  # fmt: skip


def stable() -> tuple[Route, ...]:
    return tuple(route for route in ROUTES if route.status == "stable")


__all__ = ["API_VERSION", "OBJECT", "PACK", "ROUTES", "Route", "SSE", "stable"]
