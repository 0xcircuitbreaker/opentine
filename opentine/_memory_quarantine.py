"""``tine memory quarantine NOTE``: a signed, held record that a note is poisoned (0.61).

A quarantine is an ordinary memory note (``opentine.memory``, no new kind)
that ``supersedes`` the quarantined note and carries the tag ``quarantine``;
its text says why. Because it supersedes the note, ``list``, ``recall`` and
MCP ``recall`` stop serving the note at once.

A loop that can delete a ref could delete the quarantine and serve the note
again, so (as 0.57 does for loop stops and 0.59 for taints) the signed record
is also kept as a held ``blob`` whose hold target starts with
``memory-quarantine:``; ``tine hold release`` refuses it. Readers take the
union of the ``memory/`` refs and the held copies; an unreadable holds file
raises (fail closed).

A quarantine counts when it verifies under the team keys
(``.tine/memory-team.json``); with no team file, any record whose signature
verifies on its own key counts, because counting one too many only refuses
more.
"""

from __future__ import annotations

import json
from typing import Any

TAG = "quarantine"


def _team(repo: Any) -> list[str]:
    from opentine._cli_memory import team

    return team(repo)


def _held(repo: Any) -> list[bytes]:
    from opentine.repository._holds import MEMORY_QUARANTINE, HoldError, holds_path, read_holds

    out = []
    for row in read_holds(holds_path(repo)):
        if row["target"].startswith(MEMORY_QUARANTINE):
            try:
                out.append(bytes(repo.get(row["oid"]).body))
            except Exception as exc:  # noqa: BLE001 - a held copy that cannot be read
                raise HoldError(f"held quarantine {row['oid']} cannot be read") from exc
    return out


def _records(repo: Any) -> list[Any]:
    found = []
    for ref, oid in sorted(repo.list_refs().items()):
        if ref.startswith("memory/"):
            try:
                found.append(json.loads(repo.get(oid).payload()))
            except (KeyError, ValueError, TypeError, OSError):
                continue
    for raw in _held(repo):
        try:
            found.append(json.loads(raw))
        except ValueError:
            continue
    return found


def quarantined(repo: Any) -> dict[str, dict[str, Any]]:
    """``{note digest: {quarantine, signer, why, created_at}}`` of every counted quarantine."""
    from opentine import _memory

    keys = _team(repo)
    out: dict[str, dict[str, Any]] = {}
    for record in _records(repo):
        try:
            check = _memory.check(record, team=keys)
        except (ValueError, KeyError, TypeError):
            continue
        if TAG not in check["tags"] or not check["supersedes"]:
            continue
        row = {"quarantine": check["digest"], "signer": check["signer"],
               "why": record["text"], "created_at": record["created_at"]}  # fmt: skip
        held = out.get(check["supersedes"])
        if held is None or (row["created_at"], row["quarantine"]) < (
            held["created_at"],
            held["quarantine"],
        ):
            out[check["supersedes"]] = row
    return out


def content_key(record: Any) -> str | None:
    """A note's scope, topic and folded text: a copy under a new oid has the same key."""
    import hashlib

    try:
        text = " ".join(str(record["text"]).split()).casefold()
        parts = [str(record["scope"]), str(record["topic"]).casefold(), text]
    except (KeyError, TypeError):
        return None
    return hashlib.sha256(json.dumps(parts).encode("utf-8")).hexdigest()


def blocker(repo: Any) -> Any:
    """``match(digest, record=None)``: the quarantine row for a note, by oid or same content."""
    bad = quarantined(repo)
    by_content: dict[str, dict[str, Any]] = {}
    for note, row in bad.items():
        try:
            found = content_key(json.loads(repo.get(note).payload()))
        except (KeyError, ValueError, TypeError, OSError):
            continue
        if found is not None:
            by_content.setdefault(found, row)

    def match(digest: str, record: Any = None) -> dict[str, Any] | None:
        if digest in bad or not by_content:
            return bad.get(digest)
        if record is None:
            try:
                record = json.loads(repo.get(digest).payload())
            except (KeyError, ValueError, TypeError, OSError):
                return None
        key = content_key(record)
        return by_content.get(key) if key is not None else None

    return match


def quarantine(repo: Any, note: str, key: Any, why: str, *, created_at: str | None = None,
               author: str | None = None) -> dict[str, Any]:  # fmt: skip
    """Sign, store and hold the quarantine of *note* (a stored note's digest)."""
    from opentine import _memory
    from opentine._signing_pins import key_fingerprint
    from opentine.repository import _registry_refs as refs
    from opentine.repository._holds import MEMORY_QUARANTINE, edit_holds, holds_path
    from opentine.repository._link_touch import touch_links

    if not why.strip():
        raise ValueError("a quarantine needs --why")
    try:
        target = json.loads(repo.get(note).payload())
        _memory.check(target)
    except (KeyError, ValueError, TypeError, OSError) as exc:
        raise ValueError(f"{note} is not a stored memory note") from exc
    public = key.public_key().public_bytes_raw()
    record = _memory.build(target["scope"], target["topic"], f"quarantined: {why}",
                           author=author or key_fingerprint(public), tags=[TAG],
                           supersedes=note, created_at=created_at)  # fmt: skip
    signed = _memory.sign(record, key)
    oid = refs.add_note(repo, signed)
    check = _memory.check(signed, team=_team(repo) or ())
    held = oid  # the signed note's own blob: the hold keeps it when its ref is deleted
    touch_links(repo, [held])
    row = {"oid": held, "target": f"{MEMORY_QUARANTINE}{note[12:]}:{oid[12:]}"}
    edit_holds(holds_path(repo), lambda rows: [*(r for r in rows if r != row), row])
    return {"note": note, "quarantine": oid, "signer": check["signer"], "held": held,
            "record": signed}  # fmt: skip


def promote_refusals(repo_root: Any, candidate: str) -> list[dict[str, str]]:
    """``promote.memory-quarantined`` for each quarantined note the candidate was served."""
    from opentine._memory_served import served
    from opentine._promote_checks import refusal
    from opentine.repository import Repo

    try:
        repo = Repo.open(repo_root)
    except Exception:  # noqa: BLE001 - no repository: no served notes to read
        return []
    match = blocker(repo)
    try:
        notes = served(repo, candidate)
    except (KeyError, ValueError, OSError):
        return []
    hits = [(n, row) for n in notes if (row := match(n)) is not None]
    return [refusal("promote.memory-quarantined",
                    f"{candidate} was served {n}, quarantined by {row['signer']}: "
                    f"{row['why']}") for n, row in hits]  # fmt: skip


def lineage_findings(repo_root: Any, files: dict[str, bytes],
                     variants: list[str]) -> list[dict[str, str]]:  # fmt: skip
    """``lineage.memory-quarantined`` for each variant whose mutation or eval runs consumed one."""
    from opentine._memory_index import variant_runs
    from opentine._memory_served import served
    from opentine.repository import Repo

    try:
        repo = Repo.open(repo_root)
    except Exception:  # noqa: BLE001 - no repository: no served notes to read
        return []
    if not quarantined(repo):  # an unreadable holds file raises: fail closed
        return []
    match = blocker(repo)
    out = []
    for variant, runs in variant_runs(files, variants).items():
        for run in runs:
            try:
                notes = served(repo, run)
            except (KeyError, ValueError, OSError):
                continue
            out += [{"code": "lineage.memory-quarantined", "variant": variant,
                     "detail": f"run {run} consumed quarantined note {n}"}
                    for n in notes if match(n) is not None]  # fmt: skip
    return out


__all__ = [
    "TAG",
    "blocker",
    "content_key",
    "lineage_findings",
    "promote_refusals",
    "quarantine",
    "quarantined",
]
