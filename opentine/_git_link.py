"""Linking agent runs to git commits: trailers, ``refs/notes/tine`` and lookups.

A commit says which runs produced it in two ways, both plain git:

* ``Tine-Run: <run id>`` trailers in the message, appended by the
  ``prepare-commit-msg`` hook ``tine git install-hook`` installs;
* a note under ``refs/notes/tine`` (``tine git note``), which can be added after
  the fact -- to someone else's commit, or after a rebase rewrote the message.

Every git call goes through :func:`git`: the binary bound with
``shutil.which``, the hardened ``-c`` configuration (no fsmonitor, hooks,
pager, external diff or transports) and the scrubbed environment the shell
tool uses, so a repository's own configuration cannot make a lookup run a
program. Output is bounded and nothing read from git is trusted as a run id
until it matches :data:`RUN_ID`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from opentine.tools._git_guard import HARDENED_CONFIG, git_env

TRAILER = "Tine-Run"
NOTES_REF = "refs/notes/tine"
#: What a run id may look like: a v3 object id or a legacy run id.
RUN_ID = re.compile(r"^(?:run:sha256:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9._:-]{3,199})$")
#: A revision a user names: never an option, never whitespace.
REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@^~{}:-]{0,199}$")
_TRAILER_LINE = re.compile(rf"^{TRAILER}:[ \t]*(\S+)[ \t]*$", re.MULTILINE)
MAX_OUTPUT = 16 * 1024 * 1024
MAX_RUNS_PER_COMMIT = 50
#: Variables git sets for a hook that point at *this* commit's index and repository.
#: They come from the git the user ran, not from a model, and without them a hook
#: would read the wrong index during ``git commit <paths>``.
HOOK_ENV = ("GIT_INDEX_FILE", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")


class GitLinkError(RuntimeError):
    """Git is missing, failed, or answered with something unusable."""


def git_binary() -> str:
    found = shutil.which("git")
    if not found:
        raise GitLinkError("git is not installed or not on PATH")
    return found


def git(
    cwd: Path | str,
    *args: str,
    stdin: bytes | None = None,
    keep_env: Iterable[str] = (),
    hardened: bool = True,
    timeout: float = 60.0,
) -> str:
    """Run git in *cwd* and return its stdout; raise :class:`GitLinkError` on failure."""
    env: Mapping[str, str] = git_env(os.environ)
    kept = {name: os.environ[name] for name in keep_env if name in os.environ}
    # No global attributes file either: attributes select clean/textconv programs.
    extra = ("-c", f"core.attributesFile={os.devnull}") if hardened else ()
    command = [git_binary(), *(HARDENED_CONFIG if hardened else ()), *extra, *args]
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd),
            input=stdin,
            capture_output=True,
            env={**env, **kept},
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitLinkError(f"git {args[0] if args else ''} failed: {exc}") from None
    if len(result.stdout) > MAX_OUTPUT:
        raise GitLinkError("git output exceeds the size limit")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitLinkError(detail[-1][:300] if detail else f"git exited {result.returncode}")
    return result.stdout.decode("utf-8", "replace")


def checked_revision(revision: str) -> str:
    if not REVISION.match(revision or ""):
        raise GitLinkError(f"not a revision: {revision[:80]!r}")
    return revision


def top_level(cwd: Path | str) -> Path:
    return Path(git(cwd, "rev-parse", "--show-toplevel").strip())


def resolve_commit(cwd: Path | str, revision: str) -> str:
    sha = git(
        cwd, "rev-parse", "--verify", "--end-of-options", f"{checked_revision(revision)}^{{commit}}"
    )
    return sha.strip()


def run_ids(text: str) -> list[str]:
    """Run ids named by ``Tine-Run:`` lines in *text*, in order, de-duplicated."""
    found = [match for match in _TRAILER_LINE.findall(text) if RUN_ID.fullmatch(match)]
    return list(dict.fromkeys(found))[:MAX_RUNS_PER_COMMIT]


def trailer_runs(cwd: Path | str, sha: str) -> list[str]:
    return run_ids(git(cwd, "log", "-1", "--format=%B", sha))


def note_text(cwd: Path | str, sha: str) -> str:
    try:
        return git(cwd, "notes", f"--ref={NOTES_REF}", "show", sha)
    except GitLinkError:
        return ""  # no note on this commit


@dataclass(frozen=True)
class NoteEntry:
    run_id: str
    model: str = ""
    cost: float | None = None

    def lines(self) -> list[str]:
        out = [f"{TRAILER}: {self.run_id}"]
        if self.model:
            out.append(f"Tine-Model: {_one_line(self.model)}")
        if self.cost is not None:
            out.append(f"Tine-Cost-USD: {self.cost:.6f}")
        return out


def _one_line(value: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", value)[:200]


def write_note(cwd: Path | str, sha: str, entries: list[NoteEntry]) -> list[str]:
    """Merge *entries* into the commit's ``refs/notes/tine`` note; return its run ids."""
    existing = note_text(cwd, sha)
    known = run_ids(existing)
    blocks = [existing.strip()] if existing.strip() else []
    for entry in entries:
        if entry.run_id not in known:
            blocks.append("\n".join(entry.lines()))
            known.append(entry.run_id)
    body = ("\n\n".join(blocks) + "\n").encode("utf-8")
    git(cwd, "notes", f"--ref={NOTES_REF}", "add", "-f", "-F", "-", sha, stdin=body)
    return known


def commit_runs(cwd: Path | str, sha: str) -> list[tuple[str, str]]:
    """``(run id, source)`` pairs a commit links to; source is ``trailer`` or ``note``."""
    pairs = [(run, "trailer") for run in trailer_runs(cwd, sha)]
    seen = {run for run, _ in pairs}
    for run in run_ids(note_text(cwd, sha)):
        if run not in seen:
            pairs.append((run, "note"))
            seen.add(run)
    return pairs


def pr_commits(cwd: Path | str, number: int) -> list[str]:
    """Commit shas of GitHub PR *number*, through the ``gh`` CLI."""
    gh = shutil.which("gh")
    if not gh:
        raise GitLinkError("--pr needs the GitHub CLI (gh) on PATH")
    try:
        result = subprocess.run(
            [gh, "pr", "view", str(int(number)), "--json", "commits", "--jq", ".commits[].oid"],
            cwd=str(cwd),
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitLinkError(f"gh failed: {exc}") from None
    if result.returncode != 0:
        raise GitLinkError(result.stderr.decode("utf-8", "replace").strip()[:300] or "gh failed")
    shas = [line.strip() for line in result.stdout.decode("ascii", "replace").splitlines()]
    return [sha for sha in shas if re.fullmatch(r"[0-9a-f]{40,64}", sha)][:1000]


__all__ = [
    "HOOK_ENV",
    "NOTES_REF",
    "RUN_ID",
    "TRAILER",
    "GitLinkError",
    "NoteEntry",
    "checked_revision",
    "commit_runs",
    "git",
    "git_binary",
    "note_text",
    "pr_commits",
    "resolve_commit",
    "run_ids",
    "top_level",
    "trailer_runs",
    "write_note",
]
