"""Reading Entire's ``entire/checkpoints/v1`` branch out of git, without a checkout.

Entire (entire.io, ``github.com/entireio/cli``) commits each checkpoint to a
metadata branch, sharded by id: ``<id[:2]>/<id[2:]>/metadata.json`` (the
checkpoint summary) with one numbered directory per session holding the
session's ``metadata.json``, the raw agent transcript ``full.jsonl`` (oversized
ones split into ``full.jsonl.001``, ``.002`` ...; ``full.log`` in old versions)
and ``prompt.txt``.

Every read goes through :func:`opentine._git_link.git` (hardened config,
scrubbed environment, bounded output). Blob sizes are asked for with
``cat-file -s`` before a blob is read, so an oversized one is refused without
being loaded. Paths come from the tree or from metadata and are matched against
fixed shapes before use; nothing is ever written to the filesystem.
"""

from __future__ import annotations

import re
from pathlib import Path

from opentine._git_link import GitLinkError, git

BRANCH = "entire/checkpoints/v1"
REFS = (f"refs/heads/{BRANCH}", f"refs/remotes/origin/{BRANCH}")
#: Legacy 12-hex ids and 26-character Crockford ULIDs (entireio/cli checkpoint/id).
CHECKPOINT_ID = re.compile(r"[0-9a-f]{12}|[0-9A-HJKMNP-TV-Z]{26}")
MAX_METADATA_BYTES = 1024 * 1024
MAX_PROMPT_BYTES = 256 * 1024
MAX_TRANSCRIPT_BYTES = 64 * 1024 * 1024
MAX_CHUNKS = 999
MAX_SESSIONS = 256
_CHUNK = re.compile(r"full\.jsonl\.(\d{3})")


class EntireError(ValueError):
    """The repository holds no readable Entire checkpoint branch, or a bad one."""


def find_ref(repo: Path) -> str:
    """The local checkpoint branch, else the fetched ``origin`` copy."""
    for ref in REFS:
        try:
            git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
        except GitLinkError:
            continue
        return ref
    raise EntireError(f"no {BRANCH} branch in {repo} (is Entire enabled there?)")


def checkpoint_path(checkpoint: str) -> str:
    return f"{checkpoint[:2]}/{checkpoint[2:]}"


def checkpoint_ids(repo: Path, ref: str) -> list[str]:
    """Every checkpoint id the branch holds, by its sharded directory."""
    found = []
    for name in git(repo, "ls-tree", "-d", "-r", "-z", "--name-only", ref).split("\0"):
        parts = name.split("/")
        if len(parts) == 2 and CHECKPOINT_ID.fullmatch(parts[0] + parts[1]):
            found.append(parts[0] + parts[1])
    return found


def newest_checkpoint(repo: Path, ref: str) -> str:
    """The checkpoint the most recent commit on the branch wrote."""
    log = git(repo, "log", "-n", "200", "--format=", "--name-only", "-z", ref, "--")
    for name in log.replace("\n", "\0").split("\0"):
        parts = name.split("/")
        if len(parts) >= 3 and CHECKPOINT_ID.fullmatch(parts[0] + parts[1]):
            return parts[0] + parts[1]
    raise EntireError(f"{BRANCH} holds no checkpoints")


def resolve_checkpoint(repo: Path, ref: str, wanted: str | None) -> str:
    """*wanted* (an id or unique prefix), or the newest checkpoint."""
    if not wanted:
        return newest_checkpoint(repo, ref)
    if not re.fullmatch(r"[0-9A-Za-z]{1,26}", wanted):
        raise EntireError(f"not a checkpoint id: {wanted[:40]!r}")
    matches = [item for item in checkpoint_ids(repo, ref) if item.startswith(wanted)]
    if len(matches) != 1:
        problem = "matches no checkpoint" if not matches else "is ambiguous"
        raise EntireError(f"checkpoint {wanted!r} {problem}")
    return matches[0]


def list_dir(repo: Path, ref: str, directory: str) -> list[str]:
    """Entry names directly under *directory* (empty when it is absent)."""
    try:
        listed = git(repo, "ls-tree", "-z", "--name-only", f"{ref}:{directory}")
    except GitLinkError:
        return []
    return [name for name in listed.split("\0") if name]


def read_blob(repo: Path, ref: str, path: str, limit: int) -> bytes | None:
    """The blob at *path*, ``None`` when absent; refused when over *limit*."""
    spec = f"{ref}:{path}"
    try:
        kind = git(repo, "cat-file", "-t", spec).strip()
    except GitLinkError:
        return None
    if kind != "blob":
        return None
    size = int(git(repo, "cat-file", "-s", spec).strip() or 0)
    if size > limit:
        raise EntireError(f"{path} is {size} bytes, over the {limit}-byte limit")
    return git(repo, "cat-file", "blob", spec).encode("utf-8")


def transcript_bytes(repo: Path, ref: str, session_dir: str) -> bytes | None:
    """``full.jsonl`` and its chunks in order (or legacy ``full.log``), bounded."""
    names = set(list_dir(repo, ref, session_dir))
    if "full.jsonl" not in names:
        if "full.log" in names:
            return read_blob(repo, ref, f"{session_dir}/full.log", MAX_TRANSCRIPT_BYTES)
        return None
    chunks = sorted(int(m.group(1)) for n in names if (m := _CHUNK.fullmatch(n)))[:MAX_CHUNKS]
    parts, total = [], 0
    for name in ["full.jsonl", *(f"full.jsonl.{index:03d}" for index in chunks)]:
        data = read_blob(repo, ref, f"{session_dir}/{name}", MAX_TRANSCRIPT_BYTES - total) or b""
        total += len(data)
        parts.append(data if data.endswith(b"\n") or not data else data + b"\n")
    return b"".join(parts)


def session_dirs(checkpoint: str, summary: dict) -> list[str]:
    """Each session's directory, from the summary's ``sessions[].metadata``.

    A path is used only when it is exactly ``/<shard>/<rest>/<N>/metadata.json``
    for this checkpoint: anything else (``..``, another checkpoint, a missing
    index) is skipped, never followed.
    """
    base = checkpoint_path(checkpoint)
    found = []
    sessions = summary.get("sessions")
    for entry in sessions[:MAX_SESSIONS] if isinstance(sessions, list) else []:
        meta = entry.get("metadata") if isinstance(entry, dict) else None
        match = re.fullmatch(rf"/?{re.escape(base)}/(\d{{1,4}})/metadata\.json", str(meta))
        if match:
            found.append(f"{base}/{match.group(1)}")
    return found
