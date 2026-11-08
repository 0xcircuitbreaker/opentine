"""Line attribution: which run and step wrote each line a commit added (0.42).

``tine git attribute COMMIT`` diffs the commit against its parent, matches
every added line to the recorded write that inserted it (the same matching
``tine blame`` does, :func:`opentine._blame.inserted_lines`), and stores the
result in the commit's ``refs/notes/tine`` note as one line::

    Tine-Attribution: {"schema": "opentine-line-attribution/1", ...}

The record never names the commit it is on. Each range carries the SHA-256 of
the lines it covers instead, so the note stays true when git copies it to a
rewritten commit (``notes.rewriteRef=refs/notes/tine`` makes ``rebase`` and
``commit --amend`` do that), and verification checks the hashes against the
commit the note is on now. With ``--sign-key`` the record is signed with a
``tine-sig/3`` block under the domain ``opentine.line-attribution.v1:``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opentine import _signed_doc
from opentine._actions import extract_actions
from opentine._blame import inserted_lines, same_file
from opentine._git_link import IDENTITY_ENV, NOTES_REF, GitLinkError, git, note_text

SCHEMA = "opentine-line-attribution/1"
DOMAIN = b"opentine.line-attribution.v1:"
PREFIX = "Tine-Attribution: "
MAX_ADDED_LINES = 200_000
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def added_lines(cwd: Path | str, sha: str) -> dict[str, dict[int, str]]:
    """``{path: {line number: text}}`` for the lines *sha* added over its first parent."""
    out = git(
        cwd, "diff-tree", "-p", "-U0", "--root", "--no-renames", "--no-color", "--no-ext-diff",
        "--no-textconv", "--no-commit-id", "-m", "--first-parent", sha,
    )  # fmt: skip
    files: dict[str, dict[int, str]] = {}
    current: dict[int, str] | None = None
    line = total = 0
    for raw in out.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:]
            current = None if target == "/dev/null" else files.setdefault(target[2:], {})
        elif match := _HUNK.match(raw):
            line = int(match.group(1))
        elif raw.startswith("+") and current is not None and total < MAX_ADDED_LINES:
            current[line] = raw[1:]
            line += 1
            total += 1
    return {path: lines for path, lines in files.items() if lines}


def content_hash(lines: list[str]) -> str:
    return "sha256:" + hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Writer:
    run: str
    step: str
    seq: int
    tool: str
    model: str
    order: tuple
    paths: tuple[str, ...]
    lines: frozenset[str]


def writers(runs: list[tuple[str, Any]]) -> list[Writer]:
    """Every successful recorded write of *runs* (``(name, Run)`` pairs), latest last."""
    found = []
    for rank, (name, run) in enumerate(runs):
        actions, _clipped = extract_actions(run)
        for action in actions:
            step = run.get_step(action.step_id) if action.written and not action.error else None
            if step is None:
                continue
            text = frozenset().union(*(inserted_lines(step, path) for path in action.written))
            model = action.model if not action.provider else f"{action.provider}/{action.model}"
            found.append(
                Writer(name, action.step_id, action.seq, action.tool, model,
                       (action.ts, rank, action.seq), tuple(action.written), text)
            )  # fmt: skip
    return sorted(found, key=lambda writer: writer.order)


def attribute(root: Path, added: dict[str, dict[int, str]], found: list[Writer]) -> dict[str, Any]:
    """The unsigned attribution record for *added* lines, from *found* writers."""
    files = []
    total = attributed = 0
    for path in sorted(added):
        mine = [w for w in found if any(same_file(p, root / path, path) for p in w.paths)]
        ranges: list[dict[str, Any]] = []
        texts: list[str] = []
        for number in sorted(added[path]):
            text = added[path][number]
            total += 1
            hit = next(
                (w for w in reversed(mine) if text.strip() and text.strip() in w.lines), None
            )
            if hit is None:
                continue
            attributed += 1
            last = ranges[-1] if ranges else None
            if last and last["end_line"] == number - 1 and last["step"] == hit.step:
                last["end_line"] = number
                texts.append(text)
                last["content_hash"] = content_hash(texts)
                continue
            texts = [text]
            ranges.append(
                {"start_line": number, "end_line": number, "content_hash": content_hash(texts),
                 "run": hit.run, "step": hit.step, "seq": hit.seq, "tool": hit.tool,
                 "model": hit.model}
            )  # fmt: skip
        if ranges:
            files.append({"path": path, "ranges": ranges})
    return {"schema": SCHEMA, "files": files, "lines_added": total, "lines_attributed": attributed}


def sign(record: dict[str, Any], private_key: Any) -> dict[str, Any]:
    body = {key: value for key, value in record.items() if key != "signature"}
    return {**body, "signature": _signed_doc.sign(DOMAIN, body, private_key, signer="tine")}


def read_note(cwd: Path | str, sha: str) -> dict[str, Any] | None:
    """The last attribution record in *sha*'s note (a concatenated note may hold several)."""
    for raw in reversed(note_text(cwd, sha).splitlines()):
        if raw.startswith(PREFIX):
            try:
                record = json.loads(raw[len(PREFIX) :])
            except ValueError:
                return None
            return record if isinstance(record, dict) and record.get("schema") == SCHEMA else None
    return None


def write_note(cwd: Path | str, sha: str, record: dict[str, Any]) -> None:
    """Replace any attribution line in *sha*'s note with *record*, keeping the rest."""
    kept = [raw for raw in note_text(cwd, sha).splitlines() if not raw.startswith(PREFIX)]
    while kept and not kept[-1].strip():
        kept.pop()
    line = PREFIX + json.dumps(record, sort_keys=True, separators=(",", ":"))
    body = "\n".join([*kept, "", line] if kept else [line]) + "\n"
    git(
        cwd, "notes", f"--ref={NOTES_REF}", "add", "-f", "-F", "-", sha,
        stdin=body.encode(), keep_env=IDENTITY_ENV,
    )  # fmt: skip


def verify(cwd: Path | str, sha: str, record: dict[str, Any], public_key: Any = None) -> dict:
    """Signature verdict plus whether every range's hash matches *sha*'s lines now."""
    added = added_lines(cwd, sha)
    stale = []
    for entry in record.get("files") or []:
        lines = added.get(entry.get("path"), {})
        for item in entry.get("ranges") or []:
            span = range(int(item["start_line"]), int(item["end_line"]) + 1)
            if any(n not in lines for n in span) or content_hash(
                [lines[n] for n in span]
            ) != item.get("content_hash"):
                stale.append(f"{entry.get('path')}:{span.start}-{span.stop - 1}")
    signature: dict[str, Any] = {"present": isinstance(record.get("signature"), dict)}
    if signature["present"]:
        body = {key: value for key, value in record.items() if key != "signature"}
        verdict = _signed_doc.verify(DOMAIN, body, record["signature"], public_key=public_key)
        signature.update(valid=bool(verdict.ok), state=verdict.state, basis=_signed_doc.basis(
            record["signature"], public_key))  # fmt: skip
    return {"signature": signature, "content_matches": not stale, "stale_ranges": stale}


def rewrite_ref_configured(cwd: Path | str) -> bool:
    try:
        values = git(cwd, "config", "--get-all", "notes.rewriteRef").split()
    except GitLinkError:
        return False
    return NOTES_REF in values


def configure_rewrite_ref(cwd: Path | str) -> bool:
    """Add ``notes.rewriteRef=refs/notes/tine`` to the repository's config; True if added."""
    if rewrite_ref_configured(cwd):
        return False
    git(cwd, "config", "--local", "--add", "notes.rewriteRef", NOTES_REF)
    return True


__all__ = [
    "DOMAIN",
    "PREFIX",
    "SCHEMA",
    "Writer",
    "added_lines",
    "attribute",
    "configure_rewrite_ref",
    "content_hash",
    "read_note",
    "rewrite_ref_configured",
    "sign",
    "verify",
    "write_note",
    "writers",
]
