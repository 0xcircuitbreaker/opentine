"""Landlock launcher: restrict this process, then exec the command.

Run as a script (``python -I _landlock.py --root R [--exec B]... [--net] --
argv...``) so it imports nothing from the package. It applies a Landlock
ruleset (Linux >= 5.13) that allows reading the whole system, writing only
beneath the policy root (and ``/dev/null``), executing only the listed
binaries and the dynamic loader, and, from ABI 4, no TCP bind/connect unless
``--net`` is given. The ruleset is inherited by every descendant and can not
be lifted, so ``find -exec touch`` fails at the ``execve`` even if an argument
check were bypassed.
"""

from __future__ import annotations

import ctypes
import glob
import os
import sys

_CREATE, _ADD_RULE, _RESTRICT = 444, 445, 446  # same number on every arch
_VERSION = 1
_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
EXECUTE, WRITE_FILE, READ_FILE, READ_DIR = 1, 2, 4, 8
_ABI_FS = {1: (1 << 13) - 1, 2: (1 << 14) - 1, 3: (1 << 15) - 1}
_FILE_RIGHTS = EXECUTE | WRITE_FILE | READ_FILE | (1 << 14) | (1 << 15)
_NET_TCP = 1 | 2  # LANDLOCK_ACCESS_NET_BIND_TCP | CONNECT_TCP
_SCOPES = 1 | 2  # abstract unix sockets and signals outside the domain
_LOADERS = ("/lib*/ld-*.so*", "/lib/*/ld-*.so*", "/usr/lib*/ld-*.so*", "/usr/lib/*/ld-*.so*")


class _Ruleset(ctypes.Structure):
    _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed", ctypes.c_uint64), ("fd", ctypes.c_int32)]


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def abi() -> int:
    """The kernel's Landlock ABI version, or 0 when Landlock is unavailable."""
    if not sys.platform.startswith("linux"):
        return 0
    try:
        version = _libc().syscall(_CREATE, None, ctypes.c_size_t(0), ctypes.c_uint32(_VERSION))
    except (OSError, AttributeError):
        return 0
    return max(0, int(version))


def _fail(what: str) -> None:
    err = ctypes.get_errno()
    raise OSError(err, f"landlock {what}: {os.strerror(err)}")


def restrict(root: str, executables: list[str], *, network: bool) -> None:
    """Apply the ruleset to the calling process; raise when it can not be."""
    version = abi()
    if version < 1:
        raise OSError("landlock is not available on this kernel")
    libc = _libc()
    fs = _ABI_FS.get(version, (1 << 16) - 1)
    attr = _Ruleset(fs, 0 if network or version < 4 else _NET_TCP, _SCOPES if version >= 6 else 0)
    size = 8 if version < 4 else 16 if version < 6 else 24
    ruleset = libc.syscall(_CREATE, ctypes.byref(attr), ctypes.c_size_t(size), ctypes.c_uint32(0))
    if ruleset < 0:
        _fail("create_ruleset")
    rules: list[tuple[str, int]] = [("/", READ_FILE | READ_DIR), ("/dev/null", WRITE_FILE)]
    rules.append((root, fs & ~EXECUTE))
    loaders = [path for pattern in _LOADERS for path in glob.glob(pattern)]
    rules += [(path, EXECUTE | READ_FILE) for path in [*executables, *loaders]]
    for path, access in rules:
        try:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except OSError:
            continue
        if not os.path.isdir(path):
            access &= _FILE_RIGHTS
        rule = _PathBeneath(access & fs, fd)
        added = libc.syscall(_ADD_RULE, ruleset, _PATH_BENEATH, ctypes.byref(rule), 0)
        os.close(fd)
        if added < 0:
            _fail(f"add_rule {path}")
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0:
        _fail("no_new_privs")
    if libc.syscall(_RESTRICT, ruleset, 0) < 0:
        _fail("restrict_self")
    os.close(ruleset)


def main(argv: list[str]) -> int:
    root, executables, network = "", [], False
    while argv and argv[0] != "--":
        flag = argv.pop(0)
        if flag == "--net":
            network = True
        elif flag in {"--root", "--exec"} and argv:
            value = argv.pop(0)
            root = value if flag == "--root" else root
            executables += [value] if flag == "--exec" else []
        else:
            print(f"landlock launcher: bad argument {flag!r}", file=sys.stderr)
            return 126
    command = argv[1:]
    if not root or not command:
        print("landlock launcher: --root and a command are required", file=sys.stderr)
        return 126
    try:
        restrict(root, executables, network=network)
        os.execv(command[0], command)
    except OSError as exc:
        print(f"sandbox: {exc}", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
