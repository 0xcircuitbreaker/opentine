"""The code mirror's fetch, held to the repository size limit while it runs (0.55).

``git fetch`` writes packs into the bare mirror as they arrive, so a limit
checked only after the fetch lets an oversized upstream fill the disk first. A
watchdog here samples the mirror directory while git runs and kills the fetch
the moment it passes ``max_bytes`` (or the timeout), then deletes the partial
mirror and raises ``mirror.limit-exceeded``.

A credential for a private upstream never travels in the URL or on the command
line: it reaches git as an ``Authorization`` header through ``GIT_CONFIG_*``
environment entries, read only by that one process (see
:mod:`opentine.remote._mirror_store` for where it is kept).
"""

from __future__ import annotations

import base64
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from opentine._mirror_git import GitError, _env, _pinned, command_for, size

SAMPLE_SECONDS = 0.05


def _writable_retry(func, path, _exc) -> None:
    # git writes pack and loose object files read-only; Windows refuses to delete those.
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    func(path)


def remove_tree(path: Path) -> None:
    """Delete *path* and everything under it, read-only files included, or raise ``OSError``.

    Never silent: a mirror that could not be deleted must not be reported as gone.
    """
    if not os.path.lexists(path):
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_writable_retry)
    else:  # pragma: no cover - Python 3.11
        shutil.rmtree(path, onerror=_writable_retry)
    if os.path.lexists(path):
        raise OSError(f"could not delete {path}")


def _auth_env(credential: str | None) -> dict[str, str]:
    if not credential:
        return {}
    token = base64.b64encode(credential.encode("utf-8")).decode("ascii")
    return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {token}"}  # fmt: skip


def _watch(command: list[str], env: dict[str, str], dest: Path, timeout: float,
           max_bytes: int) -> None:  # fmt: skip
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=errors, env=env)  # fmt: skip
        deadline = time.monotonic() + timeout
        reason = None
        while process.poll() is None:
            if size(dest) > max_bytes:
                reason = GitError("the upstream is larger than the mirror limit",
                                  "mirror.limit-exceeded")  # fmt: skip
            elif time.monotonic() > deadline:
                reason = GitError("git timed out", "mirror.upstream-unreachable")
            if reason is not None:
                process.kill()
                process.wait()
                raise reason
            time.sleep(SAMPLE_SECONDS)
        if size(dest) > max_bytes:  # the limit outranks however git happened to exit
            raise GitError("the upstream is larger than the mirror limit", "mirror.limit-exceeded")
        if process.returncode != 0:
            errors.seek(0)
            text = errors.read(4096).decode("utf-8", "replace").strip()
            raise GitError(text[:500] or "git failed")


def fetch(upstream: str, dest: Path, *, allow_local: bool, timeout: float, max_bytes: int,
          credential: str | None = None) -> None:  # fmt: skip
    """Mirror *upstream*'s heads and tags into the bare repo *dest*, or raise ``GitError``."""
    if upstream.startswith("-") or not (
        upstream.startswith("https://") or (allow_local and upstream.startswith("file://"))
    ):
        raise GitError("the upstream must be an https:// URL", "mirror.upstream-unverifiable")
    pin = () if upstream.startswith("file://") else _pinned(upstream, allow_local)
    if not (dest / "HEAD").is_file():
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", "--bare", str(dest)], env=_env(False),
                       capture_output=True, check=True, timeout=30)  # fmt: skip
    args = ("fetch", "--quiet", "--prune", "--no-tags", "--no-recurse-submodules",
            "--end-of-options", upstream, "+refs/heads/*:refs/heads/*",
            "+refs/tags/*:refs/tags/*")  # fmt: skip
    env = {**_env(allow_local), **_auth_env(credential)}
    try:
        _watch(command_for(dest, args, pin), env, dest, timeout, max_bytes)
        if size(dest) > max_bytes:
            raise GitError("the upstream is larger than the mirror limit", "mirror.limit-exceeded")
    except GitError as exc:
        if exc.code == "mirror.limit-exceeded":
            remove_tree(dest)
        raise


__all__ = ["SAMPLE_SECONDS", "fetch", "remove_tree"]
