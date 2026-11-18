"""Read-only git plumbing for the code mirror (0.55, ``caps.project.mirror``).

Every call runs the system ``git`` with no user or system config, no hooks,
no prompts and an allow-list of transport protocols (``https`` only, plus
``file`` when the operator allows local upstreams), against one bare mirror
directory. Nothing here can push: the mirror only fetches, and every read is
``git cat-file``, ``ls-tree``, ``log``, ``diff`` or ``for-each-ref``.

Inputs from a request (a ref, a path) are validated before they reach git, and
are always passed after ``--end-of-options`` or as ``<commit>:<path>``, never
as an option.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

_REF = re.compile(r"[A-Za-z0-9._/-]{1,240}")
_HEX = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
MAX_PATH = 4096
MAX_OUTPUT = 64 * 1024 * 1024


class GitError(RuntimeError):
    """Git failed, or a result went past a limit (``code`` is a mirror reason code)."""

    def __init__(self, message: str, code: str = "mirror.upstream-unreachable"):
        super().__init__(message)
        self.code = code


class Missing(LookupError):
    """No such ref, commit or path in the mirror."""


def _env(allow_local: bool) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.devnull,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "GIT_ALLOW_PROTOCOL": "https:file" if allow_local else "https",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }


def git(repo: Path, *args: str, timeout: float = 30, allow_local: bool = False,
        pin: tuple[str, ...] = ()) -> bytes:  # fmt: skip
    command = ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "credential.helper=",
               "-c", "http.followRedirects=false", *pin,
               "--git-dir", str(repo), *args]  # fmt: skip
    try:
        done = subprocess.run(command, capture_output=True, timeout=timeout,
                              env=_env(allow_local), check=False)  # fmt: skip
    except subprocess.TimeoutExpired as exc:
        raise GitError("git timed out", "mirror.upstream-unreachable") from exc
    if done.returncode != 0:
        raise GitError(done.stderr.decode("utf-8", "replace").strip()[:500] or "git failed")
    if len(done.stdout) > MAX_OUTPUT:
        raise GitError("git output exceeds its limit", "mirror.limit-exceeded")
    return done.stdout


def size(path: Path) -> int:
    return sum(p.stat().st_size for p in Path(path).rglob("*") if p.is_file())


def _pinned(upstream: str, allow_private: bool) -> tuple[str, ...]:
    """Refuse an upstream on a private, loopback or reserved address (SSRF), and pin the
    connection to the address checked so a DNS rebind cannot move it."""
    from urllib.parse import urlsplit

    from opentine.remote._webhooks import _address, blocked

    parts = urlsplit(upstream)
    try:
        port = parts.port or 443
        host = parts.hostname or ""
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        address = [_address(str(info[4][0])) for info in infos]
    except (OSError, ValueError, UnicodeError) as exc:
        raise GitError("the upstream host did not resolve") from exc
    if not address or (not allow_private and any(blocked(ip) for ip in address)):
        raise GitError("the upstream is a private, loopback or reserved address",
                       "mirror.upstream-unverifiable")  # fmt: skip
    shown = f"[{address[0]}]" if address[0].version == 6 else str(address[0])
    return ("-c", f"http.curloptResolve={host}:{port}:{shown}")


def fetch(upstream: str, dest: Path, *, allow_local: bool, timeout: float, max_bytes: int):
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
    git(dest, "fetch", "--quiet", "--prune", "--no-tags", "--no-recurse-submodules",
        "--end-of-options", upstream, "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*",
        timeout=timeout, allow_local=allow_local, pin=pin)  # fmt: skip
    if size(dest) > max_bytes:
        shutil.rmtree(dest, ignore_errors=True)
        raise GitError("the upstream is larger than the mirror limit", "mirror.limit-exceeded")


def object_format(repo: Path) -> str:
    return git(repo, "rev-parse", "--show-object-format").decode().strip() or "sha1"


def refs(repo: Path) -> dict[str, str]:
    """``refs/heads/*`` and ``refs/tags/*`` -> the commit each names (tags peeled)."""
    raw = git(repo, "for-each-ref", "--format=%(refname) %(objectname) %(*objectname)",
              "refs/heads", "refs/tags").decode()  # fmt: skip
    out = {}
    for line in raw.splitlines():
        name, oid, *peeled = line.split(" ")
        out[name] = peeled[0] if peeled and peeled[0] else oid
    return out


def checked_path(path: str) -> str:
    path = path.strip("/")
    parts = path.split("/") if path else []
    if len(path) > MAX_PATH or "\0" in path or any(p in ("", ".", "..") for p in parts):
        raise Missing("bad path")
    return path


def resolve(repo: Path, ref: str) -> str:
    """The commit *ref* names: a full ref, a branch or tag name, or a commit id in a ref."""
    known = refs(repo)
    if _HEX.fullmatch(ref):
        if git(repo, "cat-file", "-t", ref, timeout=10).strip() != b"commit":
            raise Missing(ref)
        return ref
    if not _REF.fullmatch(ref) or ".." in ref or ref.startswith(("-", "/")):
        raise Missing(ref)
    for name in (ref, f"refs/heads/{ref}", f"refs/tags/{ref}"):
        if name in known:
            return known[name]
    raise Missing(ref)


def _check(repo: Path, commit: str, path: str) -> tuple[str, str, int]:
    spec = f"{commit}:{path}" if path else f"{commit}^{{tree}}"
    try:
        kind = git(repo, "cat-file", "-t", spec, timeout=10).decode().strip()
        oid = git(repo, "rev-parse", "--verify", "--end-of-options", spec, timeout=10).decode()
        length = int(git(repo, "cat-file", "-s", spec, timeout=10).decode())
    except (GitError, ValueError) as exc:
        raise Missing(path) from exc
    return kind, oid.strip(), length


def tree(repo: Path, commit: str, path: str) -> list[dict[str, Any]]:
    kind, oid, _ = _check(repo, commit, path)
    if kind != "tree":
        raise Missing(path)
    out = []
    for row in git(repo, "ls-tree", "-z", "-l", oid).split(b"\0"):
        if not row:
            continue
        meta, _, name = row.partition(b"\t")
        mode, otype, entry, length = meta.decode().split(None, 3)
        name_text = name.decode("utf-8", "replace")
        out.append({"name": name_text, "path": f"{path}/{name_text}".lstrip("/"),
                    "type": otype, "mode": mode, "oid": entry,
                    "size": None if length.strip() == "-" else int(length)})  # fmt: skip
    return out


def blob(repo: Path, commit: str, path: str, max_bytes: int) -> tuple[str, bytes | None, int]:
    """``(oid, bytes or None when over max_bytes, size)`` of the file at *path*."""
    kind, oid, length = _check(repo, commit, path)
    if kind != "blob" or not path:
        raise Missing(path)
    if length > max_bytes:
        return oid, None, length
    return oid, git(repo, "cat-file", "blob", oid), length


_FORMAT = "%H%x00%P%x00%an%x00%ae%x00%aI%x00%cI%x00%s%x1e"


def _commits(raw: bytes) -> list[dict[str, Any]]:
    out = []
    for record in raw.decode("utf-8", "replace").split("\x1e"):
        fields = record.strip("\n").split("\x00")
        if len(fields) != 7:
            continue
        oid, parents, name, email, authored, committed, subject = fields
        out.append({"oid": oid, "parents": parents.split(), "author": {"name": name,
                    "email": email}, "authored_at": authored, "committed_at": committed,
                    "subject": subject})  # fmt: skip
    return out


def history(repo: Path, commit: str, path: str, skip: int, limit: int) -> list[dict[str, Any]]:
    args = ["log", f"--format={_FORMAT}", f"--skip={skip}", f"--max-count={limit}", commit]
    return _commits(git(repo, *args, "--", *([path] if path else [])))


def compare(repo: Path, base: str, head: str, limit: int) -> dict[str, Any]:
    ahead = git(repo, "rev-list", "--count", f"{base}..{head}").decode().strip()
    behind = git(repo, "rev-list", "--count", f"{head}..{base}").decode().strip()
    commits = _commits(git(repo, "log", f"--format={_FORMAT}", f"--max-count={limit}",
                           f"{base}..{head}", "--"))  # fmt: skip
    files = []
    parts = git(repo, "diff", "--name-status", "-z", "--no-renames", base, head, "--").split(b"\0")
    for status, name in zip(parts[0::2], parts[1::2], strict=False):
        if status:
            files.append({"status": status.decode(), "path": name.decode("utf-8", "replace")})
    return {"ahead_by": int(ahead), "behind_by": int(behind), "commits": commits,
            "files": files[:limit], "files_truncated": len(files) > limit}  # fmt: skip
