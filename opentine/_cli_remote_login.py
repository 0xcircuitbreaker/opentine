"""``tine remote login NAME --issuer URL --client-id ID`` (0.46): OAuth 2.0 device-code OIDC.

RFC 8628 against the issuer's discovery document: ask for a device code, show
the user code and verification URL on stderr, then poll the token endpoint at the
server-given interval (``slow_down`` adds 5 s) until approved, denied or expired.
The token (the ``id_token``, or the ``access_token`` with ``--use-access-token``)
is written owner-only to ``$XDG_CONFIG_HOME/opentine/credentials/`` and recorded
as the remote's ``token_file``: the existing credential store every remote verb
already reads. Tokens never reach stdout, stderr, logs or ``porcelain.json``.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from pathlib import Path
from typing import Any

GRANT = "urn:ietf:params:oauth:grant-type:device_code"
MAX_WAIT = 15 * 60


def add_login_parser(actions: argparse._SubParsersAction) -> None:
    login = actions.add_parser("login", help="Sign in to a remote (OIDC device-code flow)")
    login.add_argument("name", help="The remote to store the token for")
    login.add_argument("--issuer", required=True, help="OIDC issuer URL (https)")
    login.add_argument("--client-id", required=True)
    login.add_argument("--scope", default="openid profile offline_access")
    login.add_argument("--audience", help="Audience parameter some issuers require")
    login.add_argument("--use-access-token", action="store_true")
    login.add_argument("--allow-insecure", action="store_true", help="http:// issuer (dev)")
    login.add_argument("--timeout", type=float, default=30.0)


def credential_path(url: str, tenant: str | None) -> Path:
    home = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    name = hashlib.sha256(f"{url}\n{tenant or ''}".encode()).hexdigest()[:24]
    return Path(home, "opentine", "credentials", f"{name}.token")


def _http(args):
    import httpx

    return httpx.Client(timeout=args.timeout, follow_redirects=False, trust_env=False)


def _json(response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError as exc:
        raise ValueError(f"issuer returned non-JSON (HTTP {response.status_code})") from exc
    if not isinstance(body, dict):
        raise ValueError("issuer returned a non-object")
    return body


def discover(http, issuer: str, allow_insecure: bool) -> dict[str, str]:
    from opentine.repository._http import require_secure_remote

    issuer = issuer.rstrip("/")
    require_secure_remote(issuer, allow_insecure)
    meta = _json(http.get(f"{issuer}/.well-known/openid-configuration"))
    endpoints = {}
    for key in ("device_authorization_endpoint", "token_endpoint"):
        value = meta.get(key)
        if not isinstance(value, str):
            raise ValueError(f"issuer does not advertise {key}")
        require_secure_remote(value, allow_insecure)
        endpoints[key] = value
    return endpoints


def device_flow(args, http, endpoints: dict[str, str], *, sleep=time.sleep) -> dict[str, Any]:
    form = {"client_id": args.client_id, "scope": args.scope}
    if args.audience:
        form["audience"] = args.audience
    start = _json(http.post(endpoints["device_authorization_endpoint"], data=form))
    code, user_code = start.get("device_code"), start.get("user_code")
    if not isinstance(code, str) or not isinstance(user_code, str):
        raise ValueError("issuer did not return a device code")
    where = start.get("verification_uri_complete") or start.get("verification_uri")
    print(f"To sign in, open {where} and enter code {user_code}", file=sys.stderr)
    interval = max(1, int(start.get("interval") or 5))
    deadline = time.monotonic() + min(MAX_WAIT, int(start.get("expires_in") or MAX_WAIT))
    poll = {"grant_type": GRANT, "device_code": code, "client_id": args.client_id}
    while time.monotonic() < deadline:
        sleep(interval)
        body = _json(http.post(endpoints["token_endpoint"], data=poll))
        error = body.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        if error:  # access_denied, expired_token, ...: name it, never echo the body
            raise PermissionError(f"sign-in failed: {str(error)[:64]}")
        return body
    raise TimeoutError("sign-in timed out: the device code expired")


def store(path: Path, token: str) -> None:
    if not token or any(ch.isspace() for ch in token):
        raise ValueError("issuer returned an unusable token")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(".tmp")
    temporary.unlink(missing_ok=True)  # a leftover could carry wider permissions
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(token + "\n")
    os.replace(temporary, path)


def cmd_remote_login(args: argparse.Namespace, console) -> None:
    from opentine import _porcelain_config as porcelain
    from opentine._cli_errors import fail
    from opentine.repo import Repo

    try:
        repo = Repo.open(args.repo)
        settings = porcelain.load(repo.path)
        entry = settings["remotes"].get(args.name)
        if entry is None:
            raise KeyError(f"no such remote: {args.name}; `tine remote add` it first")
        with _http(args) as http:
            tokens = device_flow(args, http, discover(http, args.issuer, args.allow_insecure))
        token = tokens.get("access_token" if args.use_access_token else "id_token")
        token = token or tokens.get("access_token")
        path = credential_path(entry["url"], entry.get("tenant"))
        store(path, token if isinstance(token, str) else "")
        entry["token_file"] = path.as_posix()
        porcelain.save(repo.path, settings)
    except Exception as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(message, prefix="tine remote login: ")
    if getattr(args, "json", False):
        from opentine._cli_json import emit

        emit({"command": "remote", "action": "login", "remote": args.name,
              "token_file": path.as_posix()})  # fmt: skip
        return
    console.print(f"signed in: remote {args.name} now reads its token from its token_file")


__all__ = ["add_login_parser", "cmd_remote_login", "credential_path", "device_flow", "discover"]
