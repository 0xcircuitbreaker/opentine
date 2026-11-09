"""Carry ``refs/notes/tine`` across squash and rebase merges (0.46, ``actions/preserve-notes``).

A note is attached to a commit id, and a squash or rebase merge writes new
commit ids, so a PR's attribution notes are orphaned on merge. Given the PR's
commits (``BASE..HEAD``) and the commit the merge produced::

    python -m opentine._ci_notes --base BASE --head HEAD --merged MERGED

re-attaches them:

* **merge commit** (``MERGED`` has two parents): the PR's own commits are in
  history with their notes; nothing to do.
* **rebase**: each PR commit is matched to a rewritten commit among the last N
  first-parent commits of ``MERGED`` by ``git patch-id --stable``; each note
  moves to its match.
* **squash**: no such match exists, so every PR commit's note is copied, in
  commit order and de-duplicated, onto ``MERGED`` as one note.

A target that already carries a note is left alone unless the note is the
same, so a re-run is a no-op and a hand-written note is never overwritten.
Notes are copied byte for byte: a signed note keeps its signature (it signs
the note's content, which names its runs, not the commit id). Nothing is
pushed; the action pushes ``refs/notes/tine`` itself.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from opentine._git_link import IDENTITY_ENV, NOTES_REF, GitLinkError, checked_revision, git, git_raw

MAX_COMMITS = 1000


def _note(cwd: Path, sha: str, ref: str) -> bytes | None:
    try:
        return git_raw(cwd, "notes", f"--ref={ref}", "show", sha)
    except GitLinkError:
        return None


def _patch_id(cwd: Path, sha: str) -> str | None:
    diff = git_raw(cwd, "diff-tree", "-p", "--no-color", "--root", sha)
    out = git(cwd, "patch-id", "--stable", stdin=diff).split()
    return out[0] if out else None


def _commits(cwd: Path, *args: str) -> list[str]:
    listed = git(cwd, "rev-list", "--reverse", f"--max-count={MAX_COMMITS}", *args).split()
    return listed


def plan(cwd: Path, base: str, head: str, merged: str, ref: str = NOTES_REF) -> dict:
    """``{"mode", "moves": [[target, [sources]]]}`` for the merge; nothing is written."""
    base, head, merged = (checked_revision(r) for r in (base, head, merged))
    parents = git(cwd, "rev-list", "--parents", "-n", "1", merged).split()[1:]
    if len(parents) > 1:
        return {"mode": "merge", "moves": []}
    sources = [sha for sha in _commits(cwd, "--no-merges", f"{base}..{head}")
               if _note(cwd, sha, ref) is not None]  # fmt: skip
    if not sources:
        return {"mode": "none", "moves": []}
    count = len(_commits(cwd, "--no-merges", f"{base}..{head}"))
    landed = _commits(cwd, "--first-parent", f"--max-count={count}", merged)
    by_patch = {}
    for sha in landed:
        pid = _patch_id(cwd, sha)
        if pid:
            by_patch.setdefault(pid, sha)
    matches = {sha: by_patch.get(_patch_id(cwd, sha) or "") for sha in sources}
    if all(matches.values()) and len(landed) > 1:
        return {"mode": "rebase", "moves": [[matches[sha], [sha]] for sha in sources]}
    full = git(cwd, "rev-parse", "--verify", f"{merged}^{{commit}}").strip()
    return {"mode": "squash", "moves": [[full, sources]]}


def apply(cwd: Path, moves: list, ref: str = NOTES_REF) -> list[dict]:
    done = []
    for target, sources in moves:
        parts: list[bytes] = []
        for sha in sources:
            text = (_note(cwd, sha, ref) or b"").rstrip(b"\n")
            if text and text not in parts:
                parts.append(text)
        if not parts:
            continue
        body = b"\n".join(parts) + b"\n"
        existing = _note(cwd, target, ref)
        if existing is not None:
            state = "kept" if existing.rstrip(b"\n") == body.rstrip(b"\n") else "conflict"
        else:
            git(cwd, "notes", f"--ref={ref}", "add", "-F", "-", target, stdin=body,
                keep_env=IDENTITY_ENV)  # fmt: skip
            state = "written"
        done.append({"target": target, "sources": sources, "state": state})
    return done


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m opentine._ci_notes")
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--merged", required=True)
    p.add_argument("--ref", default=NOTES_REF)
    p.add_argument("--repo", default=".")
    args = p.parse_args(argv)
    cwd = Path(args.repo)
    try:
        result = plan(cwd, args.base, args.head, args.merged, args.ref)
        result["notes"] = apply(cwd, result.pop("moves"), args.ref)
    except GitLinkError as exc:
        print(f"preserve-notes: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
