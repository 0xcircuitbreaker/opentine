"""Passkey registration on the admin surface: for a signed-in subject, or with an invitation.

A signed-in caller (a session, or a bearer token) adds a passkey to its own
subject. Someone with no account yet registers with an invitation token: the
server mints a fresh subject (``user:<hex>``), stores the passkey's public
key, accepts the invitation for that subject and opens a session. Either
way the authenticator keeps the private key; the server never holds it.
"""

from __future__ import annotations

import secrets

from opentine.remote._admin_store import digest


def _invitation_live(store, token) -> bool:
    if not isinstance(token, str):
        return False
    wanted, now = digest(token), store.clock()
    return any(
        secrets.compare_digest(row["digest"], wanted) and row["expires"] > now
        for row in store.read()["invitations"].values()
    )


def registration(app, surface, rest, environ, sr, client):
    from opentine.remote._admin_http import Refused, _caller

    passkey, store = surface.passkey, surface.store
    fields = ("challenge", "clientDataJSON", "attestationObject", "transports", "invitation")
    request = app._json(environ, *(fields if rest == "registration" else ("invitation",)))
    invitation = request.get("invitation")
    signed_in = bool(app._headers(environ).get("authorization"))
    if signed_in:
        subject = _caller(app, surface, environ, client).subject
    elif not _invitation_live(store, invitation):
        app.auth_throttle.failed(client)
        raise Refused("401 Unauthorized", "sign in or present a live invitation", "auth.required")
    else:
        subject = ""
    if rest == "registration/options":
        if not subject:
            subject = "user:" + secrets.token_hex(8)
        return app._json_response(sr, "200 OK", passkey.registration_options(subject))
    if not subject:
        # The subject minted with the options travels in the challenge's record.
        owner = passkey.challenges.peek(request.get("challenge"), "register")
        if not owner.startswith("user:"):
            raise Refused("401 Unauthorized", "challenge belongs to a signed-in subject",
                          "auth.required")  # fmt: skip
        subject = owner
    body = passkey.register(subject, request)
    if not signed_in:
        body["tenant"] = store.accept(invitation, subject)
        body["session"] = store.open_session(subject, "passkey")
    return app._json_response(sr, "201 Created", body)


__all__ = ["registration"]
