"""Sync memory notes and prompt versions with a remote (0.47, SPEC 4.21-4.20).

``tine push`` moves one ref; memory and prompts are many small refs, so
:func:`sync` walks them: each local ``memory/*`` note the remote lacks is pushed
(a note's name is its digest, so the same name is the same note), each prompt
head or label the remote lacks or holds at an older version is pushed, and each
remote note or prompt this repository lacks is fetched and checked before a
local ref moves: a note must verify (and, with a team, be a teammate's), and a
prompt history must chain onto the local one. A remote's prompt history that
diverges from the local one is reported in ``conflicts``, never merged.
"""

from __future__ import annotations

import json
from typing import Any

from opentine import _memory, _prompt
from opentine._signed_record import RecordError
from opentine.repository import _registry_refs as refs

PREFIXES = ("memory/", "prompts/")
MAX_FETCH = 10_000


def _ours(name: str, prefixes: tuple[str, ...] = PREFIXES) -> bool:
    return name.startswith(prefixes)


def _load(repo: Any, oid: str) -> dict[str, Any]:
    return json.loads(repo.get(oid).payload())


def _remote_refs(remote: str, **kw: Any) -> dict[str, str]:
    from opentine.repository import client as rc

    timeout = kw.get("timeout", 120)
    base, namespace = rc._remote(remote, kw.get("tenant"))
    with rc._client(base, kw.get("token"), allow_insecure=kw.get("allow_insecure", False),
                    timeout=timeout) as http:  # fmt: skip
        _, listing = rc._request_json(http, "GET", rc._prefix(namespace) + "/refs",
                                      max_seconds=timeout)  # fmt: skip
    return rc._refs(listing)


def _fetch_blob(repo: Any, remote: str, oid: str, **kw: Any) -> dict[str, Any]:
    from opentine.repository import client as rc

    if not repo.has(oid):
        rc.fetch(repo, remote, wants=[oid], ref="__none__", **kw)
    return _load(repo, oid)


def _adopt_prompt(repo: Any, remote: str, name: str, oid: str, **kw: Any) -> bool:
    """Fetch the remote head's history back to the local head; adopt it if it chains."""
    local = repo.read_ref(f"prompts/{name}/head")
    chain, current = [], oid
    while current is not None and current != local and len(chain) < MAX_FETCH:
        record = _fetch_blob(repo, remote, current, **kw)
        chain.append(record)
        current = record.get("prev")
    if current != local:
        return False
    for record in reversed(chain):
        refs.push_prompt(repo, record)
    return True


def sync(
    repo: Any,
    remote: str,
    *,
    tenant: str | None = None,
    token: str | None = None,
    team: Any = (),
    prefixes: tuple[str, ...] = PREFIXES,
    **kw: Any,
) -> dict[str, Any]:
    """``{"sent", "received", "conflicts", "refused"}`` after one round each way."""
    from opentine.repository import client as rc

    kw = {"tenant": tenant, "token": token, **kw}
    theirs = _remote_refs(remote, **kw)
    local = {name: oid for name, oid in repo.list_refs().items() if _ours(name, prefixes)}
    sent: list[str] = []
    received: list[str] = []
    conflicts: list[str] = []
    refused: list[dict[str, str]] = []
    for name, oid in sorted(local.items()):
        if theirs.get(name) == oid:
            continue
        if name in theirs and not name.endswith("/head"):
            continue  # a note's name is its digest; a label the remote set stays its own
        if name in theirs:
            history = {_prompt.digest(r) for r in refs.prompt_history(repo, name.split("/")[1])}
            if theirs[name] not in history:
                continue  # behind or diverged: fetched below, never overwritten here
        rc.push(repo, remote, ref=name, **kw)
        sent.append(name)
    for name, oid in sorted(theirs.items()):
        if not _ours(name, prefixes) or local.get(name) == oid:
            continue
        parts = name.split("/")
        try:
            if parts[0] == "memory" and name not in local:
                if not team:  # no team file: no key to trust a fetched note with
                    raise RecordError("memory.untrusted-signer", "no team to trust a note with")
                record = _fetch_blob(repo, remote, oid, **kw)
                _memory.check(record, team=team)
                if refs.note_ref(record) != name:
                    raise RecordError("memory.malformed", "the ref does not name its note")
                refs.add_note(repo, record)
                received.append(name)
            elif parts[0] == "prompts" and parts[-1] == "head":
                if name in sent:
                    continue
                (
                    received if _adopt_prompt(repo, remote, parts[1], oid, **kw) else conflicts
                ).append(name)
            elif parts[0] == "prompts" and name not in local:
                record = _fetch_blob(repo, remote, oid, **kw)
                _prompt.body(record)
                if any(r == record for r in refs.prompt_history(repo, parts[1])):
                    repo.update_ref(name, oid, expected_old=None)
                    received.append(name)
        except ValueError as exc:
            refused.append({"ref": name, "reason": getattr(exc, "code", str(exc))})
    return {"sent": sent, "received": received, "conflicts": conflicts, "refused": refused}


__all__ = ["PREFIXES", "sync"]
