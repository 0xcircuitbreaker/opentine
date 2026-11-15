"""``tine serve``'s 0.52 routes: scoped tokens, CI OIDC exchange, limits and quotas.

:class:`GatewayApp` is the :class:`RemoteApp` ``reference_app`` builds. It adds

- ``GET /v1/limits`` and ``GET /v1/auth-methods``: unsigned, public documents
  (the caps schema stays as it was; ``/v1/capabilities`` only points at them);
- ``POST /v1/auth/oidc-exchange``: a CI ID token for a short-lived scoped token
  (``_ci_exchange``); the uniform ``404`` when no ``--ci-trust`` is configured,
  ``401`` (and the auth throttle) for a token nothing trusts;
- ``GET|POST /v1/tenants/{t}/tokens`` and ``DELETE .../tokens/{id}``: list,
  mint and revoke scoped tokens (``admin``; ``_token_store``);
- ``GET /v1/tenants/{t}/usage``: the tenant's limits and use (``_limits``).

Every tenant route is metered: response bytes count as egress, accepted pack
bytes as storage. A request over a limit is refused (``429``/``507``) only
after its bearer authenticates for that tenant, so a quota never answers an
outsider, and a refusal never deletes or changes anything.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from opentine.remote._auth_throttle import internal_error
from opentine.remote._limits import LimitExceeded, Limits
from opentine.remote._token_store import MAX_TTL, PREFIXES, TokenStore
from opentine.remote.app import RemoteApp

_STATUS = {429: "429 Too Many Requests", 507: "507 Insufficient Storage"}


class _Metered:
    """A response body whose bytes are charged as egress once it is closed."""

    def __init__(self, body: Iterable[bytes], charge: Any):
        self.body, self.charge, self.sent = body, charge, 0

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self.body:
            self.sent += len(chunk)
            yield chunk

    def close(self) -> None:
        try:
            closer = getattr(self.body, "close", None)
            if callable(closer):
                closer()
        finally:
            self.charge(self.sent)


class GatewayApp(RemoteApp):
    def __init__(self, service: Any, state_dir: Any, *, tokens: TokenStore, limits: Limits,
                 exchange: Any = None, **kwargs: Any):  # fmt: skip
        super().__init__(service, state_dir, **kwargs)
        self.tokens, self.limits, self.exchange = tokens, limits, exchange
        service.auth_caps = {
            "scoped_tokens": {"path": "tokens", "access": ["read", "write"],
                              "prefixes": sorted(PREFIXES.values()), "max_ttl_seconds": MAX_TTL},
            "limits": {"path": "/v1/limits", "usage": "usage", "auth_methods": "/v1/auth-methods"},
        }  # fmt: skip
        if exchange is not None:
            service.auth_caps["oidc_exchange"] = {
                "path": "/v1/auth/oidc-exchange", "providers": exchange.methods()}  # fmt: skip

    def auth_methods(self) -> dict[str, Any]:
        methods: list[dict[str, Any]] = [
            {"type": "bearer", "description": "A bearer token: the operator's, or a scoped one"},
            {"type": "scoped_token", "prefixes": sorted(PREFIXES.values()), "path": "tokens"},
        ]
        oidc = getattr(getattr(self.service.identities, "fallback", None), "verifier", None)
        if getattr(oidc, "issuer", None):
            methods.append({"type": "oidc", "issuer": oidc.issuer})
        if self.exchange is not None:
            methods.append({"type": "oidc_exchange", "path": "/v1/auth/oidc-exchange",
                            "issuers": self.exchange.methods()})  # fmt: skip
        return {"methods": methods}

    def __call__(self, environ: dict[str, Any], start_response):
        path = environ.get("PATH_INFO", "/").rstrip("/") or "/"
        method = environ.get("REQUEST_METHOD", "GET").upper()
        try:
            if path == "/v1/limits" and method == "GET":
                return self._json_response(start_response, "200 OK", self.limits.document())
            if path == "/v1/auth-methods" and method == "GET":
                return self._json_response(start_response, "200 OK", self.auth_methods())
            if path == "/v1/auth/oidc-exchange" and method == "POST":
                return self._exchange(environ, start_response)
        except Exception as exc:  # pragma: no cover - defensive, like RemoteApp
            return self._json_response(start_response, "500 Internal Server Error",
                                       internal_error(exc))  # fmt: skip
        if not path.startswith("/v1/tenants/"):
            return super().__call__(environ, start_response)
        tenant, _, resource = path[len("/v1/tenants/") :].partition("/")
        upload = (resource == "packs" and method == "POST") or (
            resource.startswith("packs/") and method == "PATCH"
        )
        raw_pack = method == "PATCH" or environ.get("CONTENT_TYPE", "").startswith(
            "application/vnd.opentine.pack"
        )
        try:
            storage = max(0, int(environ.get("CONTENT_LENGTH") or 0)) if upload and raw_pack else 0
        except ValueError:
            storage = 0  # the app refuses a malformed Content-Length itself
        try:
            self.limits.check(tenant, "egress_bytes")
            if upload:
                self.limits.check(tenant, "storage_bytes", storage)
        except LimitExceeded as exceeded:
            if self._caller_of(environ, tenant):
                return self._refuse(start_response, exceeded)
        status: list[str] = []

        def recording(line: str, headers: list, exc_info: Any = None):
            status.append(line)
            return start_response(line, headers, exc_info) if exc_info else start_response(
                line, headers)  # fmt: skip

        body = super().__call__(environ, recording)

        def charge(sent: int) -> None:
            if status and status[0].startswith("2"):
                try:
                    self.limits.charge(tenant, "egress_bytes", sent)
                    self.limits.charge(tenant, "storage_bytes", storage)
                except ValueError:  # pragma: no cover - the app accepted the tenant
                    pass

        return _Metered(body, charge)

    def _caller_of(self, environ: dict[str, Any], tenant: str) -> bool:
        try:
            identity = self.service.authenticate(self._headers(environ))
        except Exception:  # any failure: the app itself answers (401, 403, 404...)
            return False
        return identity.tenant == tenant

    def _refuse(self, start_response, exceeded: LimitExceeded):
        headers = [("Retry-After", str(exceeded.retry_after))] if exceeded.retry_after else []
        body = {"error": f"{exceeded.metric.removesuffix('_bytes')} quota exceeded"}
        return self._json_response(start_response, _STATUS[exceeded.status], body, headers)

    def _exchange(self, environ: dict[str, Any], start_response):
        if self.exchange is None:
            return self._json_response(start_response, "404 Not Found", {"error": "not found"})
        client = environ.get("REMOTE_ADDR") or "unknown"
        wait = self.auth_throttle.retry_after(client)
        if wait:
            return self._json_response(start_response, "429 Too Many Requests",
                                       {"error": "too many failed authentications"},
                                       [("Retry-After", str(wait))])  # fmt: skip
        try:
            request = self._json(environ, "token", "tenant")
            issued = self.exchange.exchange(request.get("token"), request.get("tenant"))
        except (PermissionError, ValueError):
            self.auth_throttle.failed(client)
            denied = {"error": "authentication failed"}
            return self._json_response(start_response, "401 Unauthorized", denied)
        self.auth_throttle.succeeded(client)
        return self._json_response(start_response, "201 Created", issued)

    def _dispatch(self, identity, tenant, resource, method, environ, start_response):
        if resource == "usage" and method == "GET":
            self.service._authorize(identity, "read_ref", tenant)
            return self._json_response(start_response, "200 OK", self.limits.usage(tenant))
        if resource == "tokens" or resource.startswith("tokens/"):
            return self._tokens(identity, tenant, resource[7:], method, environ, start_response)
        return super()._dispatch(identity, tenant, resource, method, environ, start_response)

    def _tokens(self, identity, tenant, token_id, method, environ, start_response):
        if method == "GET" and not token_id:
            self.service._authorize(identity, "tokens", tenant)
            body = {"tokens": self.tokens.list(tenant)}
            return self._json_response(start_response, "200 OK", body)
        if method == "POST" and not token_id:
            self.service._authorize(identity, "tokens", tenant)
            request = self._json(environ, "access", "refs", "ttl_seconds", "label")
            ttl = request.get("ttl_seconds", 90 * 86400)
            if not isinstance(ttl, int) or isinstance(ttl, bool):
                raise ValueError("ttl_seconds is an integer")
            label = request.get("label", "")
            if not isinstance(label, str):
                raise ValueError("label is a string")
            secret, record = self.tokens.mint(
                tenant, request.get("access"), request.get("refs"), ttl=ttl, label=label
            )
            self.service._audit(identity, tenant, "tokens", "minted", {"token": record["id"]})
            return self._json_response(start_response, "201 Created", {"token": secret, **record})
        if method == "DELETE" and token_id:
            self.service._authorize(identity, "tokens", tenant)
            record = self.tokens.revoke(token_id, tenant)  # another tenant's: KeyError, a 404
            self.service._audit(identity, tenant, "tokens", "revoked", {"token": token_id})
            return self._json_response(start_response, "200 OK", record)
        return self._json_response(start_response, "404 Not Found", {"error": "not found"})


__all__ = ["GatewayApp"]
