"""``tine experts PATH``: who knows this code -- agents and humans, ranked (0.47).

Every line of every text file under *PATH* at a revision is blamed
(:func:`opentine._blame_lines.blame_record`). A line a commit's line
attribution note (:mod:`opentine._line_attrib`) credits to a run counts for
that **agent**, keyed by model; every other committed line counts for the
**human** commit author, keyed by e-mail. A note's runs are **verified** when
its signature checks (against ``--pubkey`` when given) and every range's
content hash still matches the commit's lines.

Experts are ranked by attributed lines, then verified runs, then kind and id,
so the order is deterministic. Nothing is fetched; only committed history is
read, never the work tree. ``--json`` emits ``tine-experts/1``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from opentine._blame_lines import blame_record
from opentine._git_link import GitLinkError, checked_revision, git, resolve_commit, top_level
from opentine._line_attrib import read_note, verify

SCHEMA = "tine-experts/1"
MAX_FILES = 2000
_MAIL = re.compile(r"^<(.*)>$")


def _paths(cwd: Path | str, sha: str, path: str) -> tuple[list[str], bool]:
    spec = path.strip("/") or "."
    try:
        listed = git(cwd, "grep", "-I", "--name-only", "-z", "-e", "", sha, "--", spec)
    except GitLinkError:
        return [], False  # git grep exits 1 when no text file matches
    names = sorted(item.partition(":")[2] for item in listed.split("\0") if item)
    return names[:MAX_FILES], len(names) > MAX_FILES


class _Verdicts:
    """Per-commit note verdict: is what it credits signed and still accurate?"""

    def __init__(self, cwd: Path | str, public_key: Any) -> None:
        self.cwd, self.key, self.cache = cwd, public_key, {}

    def verified(self, sha: str) -> bool:
        if sha not in self.cache:
            try:
                record = read_note(self.cwd, sha)
                report = verify(self.cwd, sha, record, self.key) if record else None
            except (GitLinkError, ValueError, KeyError, TypeError):
                report = None
            self.cache[sha] = bool(
                report and report["signature"].get("valid") and report["content_matches"]
            )
        return self.cache[sha]


def _human(mail: str, name: str) -> str:
    match = _MAIL.match(mail.strip())
    return (match.group(1) if match else mail.strip()) or name or "unknown"


def experts(
    cwd: Path | str, path: str, *, rev: str = "HEAD", public_key: Any = None, limit: int = 0
) -> dict[str, Any]:
    """The ``tine-experts/1`` record for *path* (relative to *cwd*) at *rev*."""
    target = (Path(cwd) / path).resolve()
    base = target if target.is_dir() else target.parent
    root = top_level(base if base.is_dir() else cwd).resolve()
    if target != root and root not in target.parents:
        raise ValueError(f"{path} is outside the repository")
    path = target.relative_to(root).as_posix() if target != root else "."
    cwd = root
    sha = resolve_commit(cwd, checked_revision(rev))
    paths, clipped = _paths(cwd, sha, path)
    verdicts = _Verdicts(cwd, public_key)
    table: dict[tuple[str, str], dict[str, Any]] = {}
    total = 0
    for name in paths:
        try:
            rows = blame_record(cwd, name, rev=sha)["lines"]
        except (GitLinkError, ValueError):
            continue
        for row in rows:
            if not row["commit"]:
                continue
            total += 1
            ai = row["ai"]
            key = ("agent", ai["model"] or "unknown") if ai else (
                "human", _human(row["author_mail"], row["author"]))  # fmt: skip
            entry = table.setdefault(key, {"lines": 0, "files": set(), "commits": set(),
                                           "runs": set(), "verified": set()})  # fmt: skip
            entry["lines"] += 1
            entry["files"].add(name)
            entry["commits"].add(row["commit"])
            if ai and ai["run"]:
                entry["runs"].add(ai["run"])
                if verdicts.verified(row["commit"]):
                    entry["verified"].add(ai["run"])
    ranked = [
        {"kind": kind, "id": ident, "lines": entry["lines"],
         "share": round(entry["lines"] / total, 6) if total else 0.0,
         "files": len(entry["files"]), "commits": len(entry["commits"]),
         "runs": len(entry["runs"]), "verified_runs": len(entry["verified"])}
        for (kind, ident), entry in table.items()
    ]  # fmt: skip
    ranked.sort(key=lambda e: (-e["lines"], -e["verified_runs"], e["kind"], e["id"]))
    for position, entry in enumerate(ranked, 1):
        entry["rank"] = position
    return {
        "command": "experts",
        "schema": SCHEMA,
        "path": path,
        "revision": sha,
        "files": len(paths),
        "files_clipped": clipped,
        "total_lines": total,
        "experts": ranked[:limit] if limit > 0 else ranked,
    }


__all__ = ["MAX_FILES", "SCHEMA", "experts"]
