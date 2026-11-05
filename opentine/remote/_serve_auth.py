"""How ``tine serve`` authenticates: a static token or OIDC bearer verification.

A static token shorter than ``MIN_TOKEN_BYTES`` used to be accepted at 16 bytes;
it is now refused at startup unless ``--allow-weak-tokens`` keeps an existing
deployment running while its token is rotated. OIDC verification takes its
issuer, audience and (optionally) JWKS URL from the operator only: every URL
must be HTTPS and nothing a token says -- ``iss``, ``jku``, ``x5u`` -- is ever
fetched, so a presented token cannot make the server reach an address.
"""

from __future__ import annotations

import argparse
import os
from typing import Any

from opentine.remote.interfaces import Identity, IdentityProvider

#: Minimum static bearer token material, in bytes (256 bits).
MIN_TOKEN_BYTES = 32


def add_auth_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--allow-weak-tokens",
        action="store_true",
        help=f"Start even if the static token is shorter than {MIN_TOKEN_BYTES} bytes",
    )
    parser.add_argument("--oidc-issuer", help="Verify OIDC bearer tokens from this HTTPS issuer")
    parser.add_argument("--oidc-audience", help="Audience OIDC tokens must carry")
    parser.add_argument(
        "--oidc-jwks-uri", help="HTTPS JWKS URL (default: from the issuer's discovery document)"
    )
    parser.add_argument("--oidc-tenant-claim", default="tenant", help="Claim naming the tenant")
    parser.add_argument("--oidc-roles-claim", default="roles", help="Claim listing the roles")


def check_static_token(token: str | None, env: str, *, allow_weak: bool) -> str:
    if not token:
        raise SystemExit(f"{env} must contain the development bearer token")
    size = len(token.encode("utf-8"))
    if size < MIN_TOKEN_BYTES and not allow_weak:
        raise SystemExit(
            f"{env} holds {size} bytes of token material; at least {MIN_TOKEN_BYTES} are "
            'required (generate one with: python -c "import secrets; '
            'print(secrets.token_urlsafe(32))"), or pass --allow-weak-tokens while rotating'
        )
    return token


def _https(url: str, flag: str) -> str:
    if not url.startswith("https://") or len(url) <= len("https://"):
        raise SystemExit(f"{flag} must be an https:// URL")
    return url


def oidc_identities(args: argparse.Namespace, fetch: Any = None) -> IdentityProvider:
    from opentine.remote._jwks import OIDCError, https_fetch
    from opentine.remote._oidc import JWTVerifier
    from opentine.remote.security import OIDCIdentityProvider

    issuer = _https(args.oidc_issuer, "--oidc-issuer")
    if not args.oidc_audience:
        raise SystemExit("--oidc-audience is required with --oidc-issuer")
    fetch = fetch or https_fetch
    claims = {"tenant_claim": args.oidc_tenant_claim, "roles_claim": args.oidc_roles_claim}
    try:
        if args.oidc_jwks_uri:
            from opentine.remote._oidc import _document

            jwks_uri = _https(args.oidc_jwks_uri, "--oidc-jwks-uri")

            def refetch() -> dict[str, Any]:
                return _document(fetch(jwks_uri), "JWKS")

            verifier = JWTVerifier(
                refetch(), issuer=issuer, audience=args.oidc_audience, jwks_fetch=refetch
            )
        else:
            verifier = JWTVerifier.from_discovery(issuer, args.oidc_audience, fetch)
    except OIDCError as exc:
        raise SystemExit(f"OIDC setup failed: {exc}") from exc
    return OIDCIdentityProvider(verifier, **claims)


def serve_identities(args: argparse.Namespace, fetch: Any = None) -> IdentityProvider:
    """The identity provider ``tine serve`` was configured with."""
    if args.oidc_issuer:
        return oidc_identities(args, fetch)
    if args.oidc_jwks_uri or args.oidc_audience:
        raise SystemExit("--oidc-audience/--oidc-jwks-uri need --oidc-issuer")
    from opentine.remote.security import StaticTokenIdentityProvider

    token = check_static_token(
        os.environ.get(args.token_env), args.token_env, allow_weak=args.allow_weak_tokens
    )
    return StaticTokenIdentityProvider({token: Identity("development", args.tenant, (args.role,))})
