"""``tine integrity scan`` (0.60): find registered canaries in runs, prompts, memory, packs.

Every object in the repository (loose or in a pack) is read once, decoded and
searched for every registered canary in one pass (one compiled alternation,
so the cost per object does not grow with the number of canaries). A canary is
looked for as its UTF-8 bytes and as its JSON-escaped spelling, which is how it
sits inside a canonical-JSON run, prompt or memory note.

**The index.** Objects are content addressed, so an object scanned for a given
canary set never needs reading again. ``.tine/integrity/canary-index.sqlite``
keeps, per object id, the canary-set digest it was scanned under and the
canaries it held. A scan reads only objects not yet scanned under the current
set; everything else answers from the index. The counts in the result
(``objects``, ``read``, ``cached``) prove the cost: after a first scan, a scan
of a repository that grew by *k* objects reads *k* objects, however many it
held before. Registering a new canary changes the set digest and rescans.

Surfaces: an object reachable from a ``prompts/`` ref is ``prompts``, from a
``memory/`` ref ``memory``, any other object ``runs``; ``--file`` adds files
(an exported pack or bundle) searched as raw bytes, surface ``packs``.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from opentine._canary_norm import VERSION, fold

INDEX = Path(".tine") / "integrity" / "canary-index.sqlite"
MAX_WALK = 100_000


def _pattern(rows: list[dict[str, Any]]) -> tuple[re.Pattern[bytes] | None, dict[Any, str]]:
    spelled: dict[Any, str] = {}
    for row in rows:
        spelled.setdefault(fold(row["_text"]), row["canary_sha256"])
        text = row["_text"]
        spelled[text.encode("utf-8")] = row["canary_sha256"]
        escaped = json.dumps(text, ensure_ascii=False)[1:-1].encode("utf-8")
        spelled.setdefault(escaped, row["canary_sha256"])
    if not spelled:
        return None, spelled
    ordered = sorted((b for b in spelled if isinstance(b, bytes)), key=lambda b: (-len(b), b))
    return re.compile(b"|".join(re.escape(b) for b in ordered)), spelled


def search(data: bytes, pattern: re.Pattern[bytes] | None, spelled: dict[Any, str]) -> set[str]:
    """The canary digests found in *data*, byte-exact or after :func:`fold` (case,
    whitespace, zero-width and lookalike mutations)."""
    if pattern is None:
        return set()
    found = {spelled[m.group(0)] for m in pattern.finditer(data)}
    text = data.decode("utf-8", errors="replace")
    if "\\u" in text:
        text += "\n" + _unescape(text)
    folded = fold(text)
    return found | {sha for k, sha in spelled.items() if isinstance(k, str) and k in folded}


def _unescape(text: str) -> str:
    return re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)


def _surfaces(repo: Any) -> dict[str, str]:
    from opentine.kernel import ObjectEnvelope, validate_links

    out: dict[str, str] = {}
    for name, tip in sorted(repo.list_refs().items()):
        surface = "prompts" if "prompts/" in name else "memory" if "memory/" in name else None
        if surface is None or not isinstance(tip, str):
            continue
        queue = [tip]
        while queue and len(out) < MAX_WALK:
            oid = queue.pop()
            if oid in out or not repo.has(oid):
                continue
            out[oid] = surface
            try:
                queue += list(validate_links(ObjectEnvelope.decode(repo.raw(oid), oid)))
            except Exception:  # noqa: BLE001 - an unreadable link ends the walk there
                continue
    return out


def _open_index(root: Path) -> sqlite3.Connection:
    """The index, opened without following links; a linked or odd path is not used
    (an in-memory cache instead, so every object is read)."""
    from opentine._actions_trust import check_location, connect

    path = Path(root) / INDEX
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        check_location(path)
        db = connect(path)
    except (ValueError, sqlite3.Error):
        db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE IF NOT EXISTS scanned (oid TEXT PRIMARY KEY, canaries TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS hits (oid TEXT, canary TEXT, PRIMARY KEY (oid, canary))")
    return db


def _stamp(root: Path, key: str, oid: str, hits: list[str]) -> str:
    """A ``scanned`` row's value: the scan key bound (HMAC under this user's local
    secret) to the object id, its hits and the index location, so a row edited,
    copied or planted by whoever can write ``.tine/`` does not verify (audit fs-1)."""
    from opentine._actions_trust import keyed_stamp

    stamp = f"{key}\0{oid}\0{','.join(sorted(hits))}"
    return keyed_stamp(stamp, (Path(root).absolute() / INDEX).as_posix()).rsplit(":", 1)[1]


def _registrations(repo: Any) -> set[str]:
    """Held canary registrations (0.60): they hold the canary by design, never a leak."""
    from opentine._canary import _row
    from opentine.repository._holds import CANARY_HOLD, holds_path, read_holds

    out = set()
    for row in read_holds(holds_path(repo)):
        if row["target"].startswith(CANARY_HOLD):
            try:
                if _row(json.loads(repo.get(row["oid"]).body), set()) is not None:
                    out.add(row["oid"])
            except Exception:  # noqa: BLE001 - not a registration: it is scanned
                continue
    return out


def _scan_objects(root: Path, rows: list[dict[str, Any]], key: str) -> tuple[list, dict]:
    from opentine.kernel import ObjectEnvelope
    from opentine.repo import Repo

    pattern, spelled = _pattern(rows)
    repo = Repo.open(root)
    held = _registrations(repo)
    oids = [oid for oid in repo.iter_oids() if oid not in held]
    counts = {"objects": len(oids), "read": 0, "cached": 0}
    found: list[tuple[str, str]] = []
    db = _open_index(root)
    try:
        known = dict(db.execute("SELECT oid, canaries FROM scanned"))
        cached_hits: dict[str, list[str]] = {}
        for o, c in db.execute("SELECT oid, canary FROM hits"):
            cached_hits.setdefault(o, []).append(c)
        for oid in oids:
            if oid in known and known[oid] == _stamp(root, key, oid, cached_hits.get(oid, [])):
                counts["cached"] += 1
                continue
            counts["read"] += 1
            try:
                body = ObjectEnvelope.decode(repo.raw(oid), oid).body
            except Exception:  # noqa: BLE001 - an unreadable object is searched as stored
                body = repo.raw(oid)
            hits = sorted(search(body, pattern, spelled))
            db.execute("DELETE FROM hits WHERE oid = ?", (oid,))
            db.executemany("INSERT INTO hits VALUES (?, ?)", [(oid, c) for c in hits])
            db.execute("INSERT OR REPLACE INTO scanned VALUES (?, ?)",
                       (oid, _stamp(root, key, oid, hits)))  # fmt: skip
        db.commit()
        present = set(oids)
        found = [(o, c) for o, c in db.execute("SELECT oid, canary FROM hits ORDER BY oid, canary")
                 if o in present]  # fmt: skip
    finally:
        db.close()
    surfaces = _surfaces(repo) if found else {}
    return [(surfaces.get(o, "runs"), o, c) for o, c in found], counts


def scan(root: Path, files: list[str] | None = None) -> dict[str, Any]:
    """``{ok, canaries, counts, matches}``; ``ok`` is false when any canary was found."""
    from opentine._canary import load, public, set_digest

    rows = load(Path(root))
    rows_key = set_digest(rows)
    key = f"{rows_key}:{VERSION}"
    matches: list[tuple[str, str, str]] = []
    counts = {"objects": 0, "read": 0, "cached": 0, "files": 0}
    if rows and (Path(root) / ".tine").is_dir():
        found, scanned = _scan_objects(Path(root), rows, key)
        matches += found
        counts.update(scanned)
    pattern, spelled = _pattern(rows)
    for name in files or []:
        counts["files"] += 1
        data = Path(name).read_bytes()
        matches += [
            ("packs", Path(name).as_posix(), c) for c in sorted(search(data, pattern, spelled))
        ]
    by_sha = {row["canary_sha256"]: row for row in rows}
    out = [{"surface": s, "where": w, "canary_sha256": c, "holdout": by_sha[c]["holdout"]}
           for s, w, c in matches]  # fmt: skip
    return {"ok": not out, "canaries": [public(r) for r in rows], "canary_set_sha256": rows_key,
            "counts": {**counts, "matches": len(out)}, "matches": out}  # fmt: skip


__all__ = ["INDEX", "scan", "search"]
