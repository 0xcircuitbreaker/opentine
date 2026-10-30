"""Bundles over any plain git remote: ``tine bundle push|fetch REMOTE``.

The remote holds one ref, ``refs/tine/bundle``: a commit whose tree is a single
``bundle.tine`` blob (see :mod:`opentine._bundle`). Each push is a new commit
whose parent is the commit it replaces, so git's own fast-forward check refuses
a push that raced another one. Nothing else in the remote is read or written,
so a GitHub, Gitea, Radicle or bare repository works without an opentine server.

Every git call runs in a throwaway bare repository with an argument list (no
shell), the scrubbed environment and hardened ``-c`` set of
:mod:`opentine.tools._git_guard`, only the ``file``, ``https`` and ``ssh``
protocols, and a timeout. Fetched bytes are size-capped, then verified in full
by :func:`opentine._bundle.unbundle` before any local ref moves.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from opentine import _bundle
from opentine._git_link import git_binary
from opentine.repo import Repo
from opentine.tools._git_guard import HARDENED_CONFIG, git_env

REMOTE_REF = "refs/tine/bundle"
BLOB = "bundle.tine"
_PROTOCOLS = (
    "-c", "protocol.file.allow=always",
    "-c", "protocol.https.allow=always",
    "-c", "protocol.ssh.allow=always",
    "-c", "user.name=opentine",
    "-c", "user.email=opentine@localhost",
)  # fmt: skip
_SMALL = 1024 * 1024


class GitTransportError(ValueError):
    """git is missing, failed, timed out or returned something unusable."""


def _git(cwd: Path, *args: str, stdin: bytes | None = None, timeout: float, limit: int = _SMALL):
    try:
        where = () if args[0] == "init" else (f"--git-dir={cwd}",)
        command = [git_binary(), *HARDENED_CONFIG, *_PROTOCOLS, *where, *args]
        result = subprocess.run(
            command,
            cwd=str(cwd),
            input=stdin,
            capture_output=True,
            env=git_env(os.environ),
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        raise GitTransportError(f"git {args[0]} failed: {exc}") from None
    if result.returncode != 0:
        lines = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitTransportError(f"git {args[0]}: {lines[-1][:300] if lines else 'failed'}")
    if len(result.stdout) > limit:
        raise GitTransportError(f"git {args[0]} output exceeds the size limit")
    return result.stdout


def remote_spec(remote: str) -> str:
    """A git URL as given, or a local path made absolute (git runs elsewhere)."""
    if not remote or remote.startswith("-") or "::" in remote or any(c < " " for c in remote):
        raise GitTransportError(f"refusing git remote {remote[:80]!r}")
    if "://" in remote:
        scheme = remote.split("://", 1)[0].casefold()
        if scheme not in {"file", "https", "ssh"}:
            raise GitTransportError(f"unsupported git remote scheme: {scheme}")
        return remote
    if Path(remote).exists():
        return str(Path(remote).resolve())
    return remote  # scp-like ``user@host:path``


def _remote_head(work: Path, url: str, timeout: float) -> str | None:
    out = _git(work, "ls-remote", url, REMOTE_REF, timeout=timeout).decode("ascii", "replace")
    for line in out.splitlines():
        sha, _, name = line.partition("\t")
        if name == REMOTE_REF and len(sha) in (40, 64):
            return sha
    return None


def push(repo: Repo, remote: str, refs: list[str] | None, *, timeout: float = 120.0) -> dict:
    url = remote_spec(remote)
    data = _bundle.create(repo, refs)
    with tempfile.TemporaryDirectory(prefix="tine-git-") as tmp:
        work = Path(tmp)
        _git(work, "init", "-q", "--bare", ".", timeout=timeout)
        parent = _remote_head(work, url, timeout)
        if parent:
            _git(work, "fetch", "-q", "--no-tags", url, REMOTE_REF, timeout=timeout)
        blob = _git(work, "hash-object", "-w", "--stdin", stdin=data, timeout=timeout)
        tree = _git(
            work, "mktree", stdin=b"100644 blob " + blob.strip() + b"\t" + BLOB.encode() + b"\n",
            timeout=timeout,
        )  # fmt: skip
        extra = ["-p", parent] if parent else []
        commit = _git(
            work, "commit-tree", tree.decode().strip(), *extra, "-m", "opentine bundle",
            timeout=timeout,
        ).decode().strip()  # fmt: skip
        _git(work, "push", "-q", url, f"{commit}:{REMOTE_REF}", timeout=timeout)
    return {"remote": remote, "ref": REMOTE_REF, "commit": commit, "bytes": len(data)}


def fetch(
    repo: Repo, remote: str, name: str, *, force: bool = False, timeout: float = 120.0
) -> dict:
    url = remote_spec(remote)
    with tempfile.TemporaryDirectory(prefix="tine-git-") as tmp:
        work = Path(tmp)
        _git(work, "init", "-q", "--bare", ".", timeout=timeout)
        if _remote_head(work, url, timeout) is None:
            raise KeyError(f"remote has no {REMOTE_REF}: {remote}")
        _git(work, "fetch", "-q", "--no-tags", url, f"+{REMOTE_REF}:{REMOTE_REF}", timeout=timeout)
        spec = f"{REMOTE_REF}:{BLOB}"
        size = int(_git(work, "cat-file", "-s", spec, timeout=timeout).strip() or b"-1")
        if not 0 <= size <= _bundle.MAX_BUNDLE_BYTES:
            raise _bundle.BundleError("remote bundle exceeds the maximum size")
        data = _git(work, "cat-file", "blob", spec, timeout=timeout, limit=size)
    result = _bundle.unbundle(repo, data, name, force=force)
    return {"remote": remote, **result}


__all__ = ["REMOTE_REF", "GitTransportError", "fetch", "push", "remote_spec"]
