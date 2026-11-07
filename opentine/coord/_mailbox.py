"""Fleet mailboxes: ``coord/mailbox/<fleet id>/<member>`` (``tine fleet send``).

A mailbox's value is ``{"fleet", "member", "next": N, "pending": [MESSAGE]}``
with each message ``{"id", "text", "from", "sent_ms"}``. :func:`send` appends
one and :func:`take` empties ``pending``, each by compare-and-swap, so a message
is delivered exactly once even when a send races a delivery. Delivered messages
stay readable in the annotation chain (:func:`opentine.coord._store.history`).
"""

from __future__ import annotations

import re
from typing import Any

from opentine.coord._store import read, swap
from opentine.coord._tasks import MAX_ATTEMPTS, now_ms

KIND = "mailbox"
PREFIX = "coord/mailbox/"
FLEET_ID = re.compile(r"^[0-9a-f]{12}$")
MAX_TEXT = 64 * 1024
MAX_PENDING = 256
_MEMBER = re.compile(r"[^a-z0-9._-]")


def member_slug(member: str) -> str:
    slug = _MEMBER.sub("-", str(member).lower()).strip(".-")[:64]
    if not slug:
        raise ValueError(f"invalid fleet member: {member!r}")
    return slug


def ref_name(fleet: str, member: str) -> str:
    if not isinstance(fleet, str) or not FLEET_ID.fullmatch(fleet):
        raise ValueError(f"invalid fleet id: {fleet!r}")
    return f"{PREFIX}{fleet}/{member_slug(member)}"


def _empty(fleet: str, member: str) -> dict[str, Any]:
    return {"fleet": fleet, "member": member_slug(member), "next": 1, "pending": []}


def send(repo: Any, fleet: str, member: str, text: str, sender: str = "operator") -> dict:
    """Queue *text* for *member*; the queued message."""
    if not isinstance(text, str) or not text or len(text) > MAX_TEXT:
        raise ValueError("a message is non-empty text of at most 64 KiB")
    name = ref_name(fleet, member)
    for _ in range(MAX_ATTEMPTS):
        oid, value = read(repo, name, KIND)
        value = value or _empty(fleet, member)
        if len(value["pending"]) >= MAX_PENDING:
            raise ValueError(f"mailbox {name} is full ({MAX_PENDING} undelivered messages)")
        message = {"id": int(value["next"]), "text": text, "from": str(sender)[:256],
                   "sent_ms": now_ms()}  # fmt: skip
        new = {**value, "next": message["id"] + 1, "pending": [*value["pending"], message]}
        if swap(repo, name, KIND, new, oid) is not None:
            return message
    raise ValueError(f"mailbox {name}: too many concurrent writers")


def take(repo: Any, fleet: str, member: str) -> list[dict[str, Any]]:
    """Every pending message for *member*, removed from the mailbox (once)."""
    name = ref_name(fleet, member)
    for _ in range(MAX_ATTEMPTS):
        oid, value = read(repo, name, KIND)
        if value is None or not value["pending"]:
            return []
        if swap(repo, name, KIND, {**value, "pending": []}, oid) is not None:
            return list(value["pending"])
    return []


def pending(repo: Any, fleet: str, member: str) -> list[dict[str, Any]]:
    value = read(repo, ref_name(fleet, member), KIND)[1]
    return list(value["pending"]) if value else []


__all__ = ["KIND", "member_slug", "pending", "ref_name", "send", "take"]
