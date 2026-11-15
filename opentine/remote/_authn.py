"""Pluggable login for the 0.52 admin surface: passkeys, and a local dev authenticator.

An :class:`Authenticator` turns a ceremony into a *subject*; the admin
surface then opens a session for it (``_admin_store``). Two ship here:

* :class:`PasskeyAuthenticator` -- WebAuthn (``_webauthn``) against a
  configured RP id and origin. The hosted service's login is this one. The
  server stores public keys only and never holds a user signing key.
* :class:`DevAuthenticator` -- ``tine serve --dev-login``: names a subject
  with no proof at all. Loopback development only; never on a public host.

Provider sign-in (GitHub, Google, an OIDC issuer) is *identity linking*
only: it can attach a verified provider identity to a subject, never mint a
signing key or vouch for a signature. ``tine serve`` implements none.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from typing import Any, Protocol

from opentine.remote import _webauthn
from opentine.remote._admin_store import AdminStore, check_text

CHALLENGE_TTL = 300.0
MAX_CHALLENGES = 10_000


class Authenticator(Protocol):
    name: str

    def capabilities(self) -> dict[str, Any]: ...


class DevAuthenticator:
    name = "dev"

    def capabilities(self) -> dict[str, Any]:
        return {"path": "auth/dev/login", "proof": "none (development only)"}

    def login(self, request: dict[str, Any]) -> str:
        return "dev:" + check_text(request.get("subject"), "subject")


class _Challenges:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self._rows: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.Lock()

    def issue(self, purpose: str, subject: str) -> str:
        challenge = _webauthn.b64url(secrets.token_bytes(32))
        now = self.clock()
        with self._lock:
            self._rows = {k: v for k, v in self._rows.items() if v[2] > now}
            if len(self._rows) >= MAX_CHALLENGES:
                raise PermissionError("too many outstanding challenges")
            self._rows[challenge] = (purpose, subject, now + CHALLENGE_TTL)
        return challenge

    def peek(self, challenge: Any, purpose: str) -> str:
        """The subject a live *challenge* was issued for, leaving it unused."""
        with self._lock:
            row = self._rows.get(challenge) if isinstance(challenge, str) else None
        if row is None or row[0] != purpose or row[2] <= self.clock():
            raise _webauthn.WebAuthnError("unknown or expired challenge")
        return row[1]

    def take(self, challenge: Any, purpose: str) -> str:
        """The subject a live, unused *challenge* was issued for (single use)."""
        with self._lock:
            row = self._rows.pop(challenge, None) if isinstance(challenge, str) else None
        if row is None or row[0] != purpose or row[2] <= self.clock():
            raise _webauthn.WebAuthnError("unknown or expired challenge")
        return row[1]


class PasskeyAuthenticator:
    name = "passkey"

    def __init__(self, store: AdminStore, *, rp_id: str, origin: str, rp_name: str = "OpenTine"):
        if not rp_id or not origin.startswith(("https://", "http://localhost", "http://127.")):
            raise ValueError("passkeys need an RP id and an https (or localhost) origin")
        self.store, self.rp_id, self.origin, self.rp_name = store, rp_id, origin, rp_name
        self.challenges = _Challenges()

    def capabilities(self) -> dict[str, Any]:
        return {"rp_id": self.rp_id, "algorithms": [_webauthn.ES256, _webauthn.EDDSA],
                "attestation": "none", "paths": ["auth/passkey/registration",
                                                 "auth/passkey/assertion"]}  # fmt: skip

    def registration_options(self, subject: str) -> dict[str, Any]:
        user_id = _webauthn.b64url(hashlib.sha256(subject.encode()).digest())
        return {
            "challenge": self.challenges.issue("register", subject),
            "rp": {"id": self.rp_id, "name": self.rp_name},
            "user": {"id": user_id, "name": subject, "displayName": subject},
            "pubKeyCredParams": [{"type": "public-key", "alg": _webauthn.ES256},
                                 {"type": "public-key", "alg": _webauthn.EDDSA}],
            "attestation": "none",
            "timeout": int(CHALLENGE_TTL * 1000),
            "authenticatorSelection": {"residentKey": "required",
                                       "userVerification": "preferred"},
        }  # fmt: skip

    def register(self, subject: str, request: dict[str, Any]) -> dict[str, Any]:
        owner = self.challenges.take(request.get("challenge"), "register")
        if owner != subject:
            raise _webauthn.WebAuthnError("challenge was issued to another subject")
        row = _webauthn.verify_registration(
            request, request["challenge"], rp_id=self.rp_id, origin=self.origin
        )
        credential_id = row.pop("credential_id")
        self.store.add_credential(credential_id, {**row, "subject": subject})
        return {"credential_id": credential_id, "subject": subject, "alg": row["alg"]}

    def assertion_options(self) -> dict[str, Any]:
        return {"challenge": self.challenges.issue("login", ""), "rpId": self.rp_id,
                "allowCredentials": [], "userVerification": "preferred",
                "timeout": int(CHALLENGE_TTL * 1000)}  # fmt: skip

    def login(self, request: dict[str, Any]) -> str:
        self.challenges.take(request.get("challenge"), "login")
        credential_id = request.get("credential_id")
        credential = self.store.credential(credential_id) if isinstance(credential_id, str) else 0
        if not credential:
            raise _webauthn.WebAuthnError("unknown credential")
        counter = _webauthn.verify_assertion(
            request, credential, request["challenge"], rp_id=self.rp_id, origin=self.origin
        )
        self.store.bump_counter(credential_id, counter)
        return credential["subject"]


__all__ = ["Authenticator", "DevAuthenticator", "PasskeyAuthenticator"]
