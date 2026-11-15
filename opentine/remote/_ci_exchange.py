"""CI OIDC exchange (0.52): a CI job's ID token for a short-lived scoped token.

``tine serve --ci-trust FILE`` reads the operator's trust configuration::

    {"issuers": [{
        "name": "github", "provider": "github",          # github | gitlab | forgejo
        "issuer": "https://token.actions.githubusercontent.com",  # preset for github/gitlab
        "audience": "https://tine.example",
        "jwks_file": "github.jwks.json",                  # or "jwks": {...} or "jwks_uri"
        "rules": [{"claims": {"repository": "acme/app", "ref": "refs/heads/*"},
                   "tenant": "acme", "access": "write", "refs": ["heads/ci/"],
                   "ttl_seconds": 900}]}]}

``POST /v1/auth/oidc-exchange`` with ``{"token": JWT}`` (and optionally
``"tenant"``) verifies the JWT's signature, issuer, audience and expiry against
that issuer's configured JWKS (``_oidc.JWTVerifier``; nothing the token names
is fetched), then takes the **first** rule whose every claim matches: equal, or
for a value ending in ``*`` a prefix. Each rule must pin the provider's
identifying claim (``repository`` or ``repository_owner`` on GitHub and Forgejo,
``project_path`` or ``namespace_path`` on GitLab), so no rule can admit every
repository of a public CI service. A matched rule mints a ``tine_ci_`` token
(``_token_store``) of at most an hour; a JWT ``jti`` is exchanged once.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine.remote._jwks import OIDCError
from opentine.remote._token_scope import ACCESS, check_namespaces
from opentine.remote._token_store import MAX_CI_TTL, TokenStore, iso

PRESETS = {
    "github": ("https://token.actions.githubusercontent.com", ("repository", "repository_owner")),
    "gitlab": ("https://gitlab.com", ("project_path", "namespace_path")),
    "forgejo": (None, ("repository", "repository_owner")),
}
DEFAULT_CI_TTL = 900


def _rule(raw: Any, identifying: tuple[str, ...]) -> dict[str, Any]:
    keys = {"claims", "tenant", "access", "refs", "ttl_seconds"}
    if not isinstance(raw, dict) or set(raw) - keys:
        raise ValueError("a rule has claims, tenant, access, refs and optional ttl_seconds")
    claims = raw.get("claims")
    if not isinstance(claims, dict) or not claims:
        raise ValueError("a rule must match at least one claim")
    if not all(isinstance(k, str) and isinstance(v, str) and v for k, v in claims.items()):
        raise ValueError("rule claims map claim names to non-empty strings")
    if not any(name in claims and claims[name] != "*" for name in identifying):
        raise ValueError(f"a rule must pin one of {', '.join(identifying)}")
    if raw.get("access") not in ACCESS:
        raise ValueError("rule access is read or write")
    ttl = raw.get("ttl_seconds", DEFAULT_CI_TTL)
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 60 <= ttl <= MAX_CI_TTL:
        raise ValueError(f"rule ttl_seconds is 60 to {MAX_CI_TTL}")
    from opentine.remote.backend import valid_tenant

    valid_tenant(raw.get("tenant"))
    refs = check_namespaces(raw.get("refs"))
    return {"claims": claims, "tenant": raw["tenant"], "access": raw["access"], "refs": refs,
            "ttl": ttl}  # fmt: skip


def _matches(rule: dict[str, Any], claims: dict[str, Any]) -> bool:
    for name, want in rule["claims"].items():
        value = claims.get(name)
        if not isinstance(value, str):
            return False
        if want.endswith("*") and not value.startswith(want[:-1]):
            return False
        if not want.endswith("*") and value != want:
            return False
    return True


class Issuer:
    def __init__(self, raw: Any, base: Path, fetch: Any = None):
        from opentine.remote._oidc import JWTVerifier, _document

        if not isinstance(raw, dict):
            raise ValueError("an issuer is an object")
        self.name, self.provider = raw.get("name"), raw.get("provider")
        if self.provider not in PRESETS or not isinstance(self.name, str) or not self.name:
            raise ValueError(f"an issuer needs a name and a provider of {', '.join(PRESETS)}")
        default, identifying = PRESETS[self.provider]
        issuer = raw.get("issuer") or default
        if not isinstance(issuer, str) or not issuer.startswith("https://"):
            raise ValueError(f"issuer {self.name}: an https:// issuer is required")
        audience = raw.get("audience")
        if not isinstance(audience, str) or not audience:
            raise ValueError(f"issuer {self.name}: an audience is required")
        rules = raw.get("rules")
        if not isinstance(rules, list) or not rules:
            raise ValueError(f"issuer {self.name}: at least one rule is required")
        self.rules = [_rule(rule, identifying) for rule in rules]
        self.issuer = issuer
        refetch = None
        if "jwks" in raw:
            jwks = raw["jwks"]
        elif "jwks_file" in raw:
            jwks = _document((base / raw["jwks_file"]).read_bytes(), "JWKS")
        elif isinstance(raw.get("jwks_uri"), str) and raw["jwks_uri"].startswith("https://"):
            from opentine.remote._jwks import https_fetch

            uri, getter = raw["jwks_uri"], fetch or https_fetch

            def refetch() -> dict[str, Any]:
                return _document(getter(uri), "JWKS")

            jwks = refetch()
        else:
            raise ValueError(f"issuer {self.name}: give jwks, jwks_file or an https jwks_uri")
        self.verify = JWTVerifier(jwks, issuer=issuer, audience=audience, jwks_fetch=refetch)


class CIExchange:
    def __init__(self, issuers: list[Issuer], store: TokenStore):
        self.issuers = issuers
        self.store = store

    @classmethod
    def load(cls, path: str | Path, store: TokenStore, fetch: Any = None) -> CIExchange:
        path = Path(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("issuers"), list):
            raise ValueError('a CI trust file is {"issuers": [...]}')
        issuers = [Issuer(item, path.parent, fetch) for item in raw["issuers"]]
        if len({item.name for item in issuers}) != len(issuers):
            raise ValueError("issuer names must be unique")
        return cls(issuers, store)

    def methods(self) -> list[dict[str, Any]]:
        return [{"name": item.name, "provider": item.provider, "issuer": item.issuer}
                for item in self.issuers]  # fmt: skip

    def exchange(self, token: Any, tenant: Any = None) -> dict[str, Any]:
        """The issued token; ``PermissionError`` for anything not trusted."""
        if not isinstance(token, str) or token.count(".") != 2 or len(token) > 16_384:
            raise OIDCError("malformed JWT")
        claims, chosen = None, None
        for issuer in self.issuers:
            try:
                claims = issuer.verify(token)
            except OIDCError:
                continue
            chosen = issuer
            break
        if chosen is None or claims is None:
            raise OIDCError("no configured issuer verifies this token")
        for rule in chosen.rules:
            if (tenant is None or tenant == rule["tenant"]) and _matches(rule, claims):
                break
        else:
            raise OIDCError("no trust rule matches this token")
        jti = claims.get("jti")
        if isinstance(jti, str) and jti:
            until = float(claims.get("exp", 0)) + 120
            if not self.store.first_use(chosen.issuer, jti, until):
                raise OIDCError("this CI token was already exchanged")
        subject = f"ci:{chosen.name}:{claims.get('sub', '')}"[:512]
        secret, record = self.store.mint(
            rule["tenant"], rule["access"], rule["refs"], ttl=rule["ttl"], kind="ci",
            label=chosen.name, subject=subject,
        )  # fmt: skip
        return {"token": secret, "token_id": record["id"], "tenant": record["tenant"],
                "access": record["access"], "refs": record["refs"],
                "expires_at": record["expires_at"], "issued_at": iso(self.store.now())}  # fmt: skip


__all__ = ["CIExchange", "Issuer", "PRESETS"]
