"""Write a run as an Entire checkpoint (``tine export --format entire``).

The layout is the current entireio/cli git-refs backend's, the one
:mod:`opentine.trace._entire_refs` reads first: one ref,
``refs/entire/checkpoints/<id[-2:]>/<id>``, naming a commit whose tree root is
the checkpoint::

    metadata.json          CheckpointSummary (sessions[0].metadata = "/0/metadata.json")
    0/metadata.json        session Metadata (agent "Claude Code", model, token_usage)
    0/full.jsonl           the run as a Claude Code transcript (_entire_transcript)
    0/prompt.txt           the first human prompt
    0/content_hash.txt     "sha256:<hex of full.jsonl>"

The commit message is Entire's (``Checkpoint: <id>`` plus ``Entire-Session``,
``Entire-Strategy`` and ``Entire-Agent`` trailers). The checkpoint id is the
12-hex legacy form derived from the run id, so exporting the same run again
lands on the same ref, as a child commit of its tip (per-checkpoint history,
as Entire writes it) and only when the content changed. Objects are written
with git plumbing through :func:`opentine._git_link.git`; no worktree, index or
branch of the target repository is touched.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine._entire_transcript import claude_lines, first_prompt, iso
from opentine._git_link import GitLinkError, git
from opentine._version import __version__
from opentine.trace._entire_refs import ref_name

AGENT = "Claude Code"
STRATEGY = "manual-commit"
_USAGE = {
    "input": "input_tokens",
    "output": "output_tokens",
    "reasoning": "output_tokens",
    "cache_read": "cache_read_tokens",
    "cache_write_5m": "cache_creation_tokens",
    "cache_write_1h": "cache_creation_tokens",
}


def checkpoint_id(run_id: str) -> str:
    return hashlib.sha256(f"opentine-run:{run_id}".encode()).hexdigest()[:12]


def token_usage(run: Any) -> dict[str, int]:
    """Entire's ``TokenUsage`` totals over the run's model steps."""
    totals = dict.fromkeys(dict.fromkeys(_USAGE.values()), 0) | {"api_call_count": 0}
    for step in run.steps:
        if (step.v3_kind or getattr(step.kind, "value", "")) != "model":
            continue
        totals["api_call_count"] += 1
        for name, value in (step.usage or {}).items():
            if name in _USAGE and isinstance(value, int) and not isinstance(value, bool):
                totals[_USAGE[name]] += value
    return totals


def _blob(repo: Path, data: bytes) -> str:
    return git(repo, "hash-object", "-w", "--stdin", stdin=data).strip()


def _tree(repo: Path, entries: dict[str, str]) -> str:
    """A tree from ``name -> "<mode> <type> <sha>"`` entries."""
    listing = "".join(f"{entry}\t{name}\n" for name, entry in sorted(entries.items()))
    return git(repo, "mktree", stdin=listing.encode()).strip()


def checkpoint_files(run: Any, checkpoint: str) -> dict[str, bytes]:
    """The checkpoint's files, keyed by their path inside session ``0``."""
    lines = claude_lines(run, run.id)
    transcript = "".join(json.dumps(line, sort_keys=True) + "\n" for line in lines).encode()
    created = iso(run.steps[0].timestamp if run.steps else 0)
    usage = token_usage(run)
    common = {
        "cli_version": f"opentine-{__version__}",
        "checkpoint_id": checkpoint,
        "strategy": STRATEGY,
        "checkpoints_count": 1,
        "files_touched": [],
        "token_usage": usage,
    }
    meta = {
        **common,
        "session_id": run.id,
        "created_at": created,
        "agent": AGENT,
        "model": str(run.model_info or ""),
    }
    digest = "sha256:" + hashlib.sha256(transcript).hexdigest()
    summary = {
        **common,
        "sessions": [
            {
                "metadata": "/0/metadata.json",
                "transcript": "/0/full.jsonl",
                "content_hash": "/0/content_hash.txt",
                "prompt": "/0/prompt.txt",
            }
        ],
    }
    return {
        "metadata.json": json.dumps(summary, indent=2).encode(),
        "0/metadata.json": json.dumps(meta, indent=2).encode(),
        "0/full.jsonl": transcript,
        "0/prompt.txt": first_prompt(run).encode(),
        "0/content_hash.txt": digest.encode(),
    }


def _identity(repo: Path) -> tuple[str, ...]:
    """The repository's own committer, or a neutral one when none is configured."""
    try:
        if git(repo, "config", "user.name").strip() and git(repo, "config", "user.email").strip():
            return ()
    except GitLinkError:
        pass
    return ("-c", "user.name=OpenTine", "-c", "user.email=opentine@localhost")


def write_checkpoint(repo: Path, run: Any) -> dict[str, Any]:
    """Commit *run* as a checkpoint ref in the git repository at *repo*."""
    try:
        git(repo, "rev-parse", "--git-dir")
    except GitLinkError as exc:
        raise ValueError(f"{repo} is not a git repository") from exc
    checkpoint = checkpoint_id(run.id)
    ref = ref_name(checkpoint)
    files = checkpoint_files(run, checkpoint)
    session = {
        name.split("/", 1)[1]: f"100644 blob {_blob(repo, data)}"
        for name, data in files.items()
        if name.startswith("0/")
    }
    root = {"metadata.json": f"100644 blob {_blob(repo, files['metadata.json'])}"}
    root["0"] = f"040000 tree {_tree(repo, session)}"
    tree = _tree(repo, root)
    try:
        parent: str | None = git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
        parent = (parent or "").strip() or None
    except GitLinkError:
        parent = None
    if parent and git(repo, "rev-parse", f"{parent}^{{tree}}").strip() == tree:
        commit = parent  # the same run exported again: nothing new to record
    else:
        message = (
            f"Checkpoint: {checkpoint}\n\nEntire-Session: {run.id}\n"
            f"Entire-Strategy: {STRATEGY}\nEntire-Agent: {AGENT}\n"
        )
        args = ["commit-tree", tree, "-m", message, *(["-p", parent] if parent else [])]
        commit = git(repo, *_identity(repo), *args).strip()
        git(repo, "update-ref", ref, commit, parent or "")
    return {"checkpoint_id": checkpoint, "ref": ref, "commit": commit, "sessions": 1}


__all__ = ["checkpoint_files", "checkpoint_id", "token_usage", "write_checkpoint"]
