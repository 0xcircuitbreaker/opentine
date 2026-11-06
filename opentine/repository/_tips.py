"""Fetch negotiation on ref tips (P5, 0.37).

A fetch used to send every local oid as a "have": up to ~300 MB of request for a
large repository, most of it about objects the server would never walk to. A
server that advertises ``"tips"`` in its capabilities' ``negotiation`` list
accepts ``tips`` instead: the run ids (and other ref targets) the client's refs
point at. Each is a promise that the client holds that object *and its whole
history*, so the server's walk from the wants stops there (``pack.reachable``'s
*stop*); runs it meets at a tip still bring their associations, so annotations
added since reach the client (some already held may be sent again: a redundant
transfer, never a missing object).

The promise only holds in a complete repository, so a client with shallow
boundaries (a depth-limited or typed fetch left objects out) keeps sending
haves, as does every client facing a server that does not advertise ``tips``
(0.36 and older, which refuse request keys they do not know). Old clients send
haves to a new server, which answers them as before.
"""

from __future__ import annotations

from typing import Any

from opentine.kernel import KernelError, parse_oid

CAPABILITY = "tips"
#: Tips sent at most; more refs only means a larger (redundant) transfer.
MAX_TIPS = 4096


def checked_ids(values: Any, label: str, limit: int) -> list[str]:
    """*values* as a list of object ids (at most *limit*), or ``KernelError``."""
    if not isinstance(values, list) or not all(isinstance(oid, str) for oid in values):
        raise KernelError(f"pack {label} must be a list of object ids")
    if len(values) > limit:
        raise KernelError(f"pack negotiation has too many {label}")
    for oid in values:
        parse_oid(oid)
    return values


def met_tips(
    stop: frozenset[str], wants: list[str], links: dict[str, tuple[str, ...]]
) -> list[str]:
    """The runs in *stop* the walk reached (a want, or linked from a walked object)."""
    if not stop:
        return []
    met = {oid for oid in wants if oid in stop}
    met.update(link for found in links.values() for link in found if link in stop)
    return sorted(oid for oid in met if oid.startswith("run:"))


def local_tips(repo) -> list[str] | None:
    """The tips this repository can promise, or ``None`` when it must send haves."""
    if repo.shallow_oids():
        return None  # some history is missing: a tip is no promise of its ancestors
    held = sorted({oid for oid in repo.list_refs().values() if repo.has(oid)})
    return held[:MAX_TIPS]


def negotiation_fields(repo, capabilities: dict[str, Any], haves_limit: int) -> dict[str, list]:
    """The fetch request's negotiation: ``tips`` when the server takes them, else haves."""
    offered = capabilities.get("negotiation")
    if isinstance(offered, list) and CAPABILITY in offered:
        tips = local_tips(repo)
        if tips is not None:
            return {"haves": [], "tips": tips}
    # The wire protocol deliberately bounds negotiation sets. A truncated
    # have-list can only cause a redundant transfer; sending more would make
    # otherwise healthy large repositories impossible to fetch into.
    return {"haves": repo.iter_oids(limit=haves_limit, truncate=True)}
