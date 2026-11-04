"""Argument-level checks for allowlisted shell executables.

The allowlist names a program, not what it may be told to do: ``find -exec``,
``tar --to-command`` or ``sed e`` turn a harmless tool into an arbitrary
command runner, and an absolute or ``..`` path reaches outside the workspace.
Git has its own guard and is not checked here.
"""

from __future__ import annotations

import re
from pathlib import Path

# Programs whose whole purpose is to run another program.
_WRAPPERS = frozenset(
    {
        "bash", "busybox", "chroot", "dash", "doas", "env", "fish", "flock",
        "ionice", "ksh", "nice", "nohup", "script", "setsid", "sh", "stdbuf",
        "strace", "su", "sudo", "taskset", "time", "timeout", "watch", "xargs",
        "zsh",
    }
)  # fmt: skip

_DENIED: dict[str, tuple[str, ...]] = {
    "find": (
        "-exec", "-execdir", "-ok", "-okdir", "-delete",
        "-fprint", "-fprint0", "-fprintf", "-fls",
    ),
    "sed": ("-i", "--in-place"),
    "tar": (
        "--to-command", "--checkpoint-action", "--use-compress-program", "-I",
        "--rsh-command", "--info-script", "--new-volume-script", "-F",
    ),
    "rsync": ("-e", "--rsh", "--rsync-path"),
    "zip": ("-TT", "--unzip-command"),
}  # fmt: skip

# The ``e``/``w``/``W``/``r``/``R`` commands and the ``s///e`` / ``s///w`` flags.
_SED_EXEC = re.compile(
    r"(^|[;\n{}])\s*[\d,$!~ ]*(/[^/]*/[\d,$!~ ]*)?[eRrWw]|s(.).*?\3.*?\3[^;\n}]*[ew]"
)


def _name(executable: str) -> str:
    name = Path(executable).name.lower()
    return name[:-4] if name.endswith(".exe") else name


def _matches(arg: str, option: str) -> bool:
    if arg == option or arg.startswith(option + "="):
        return True
    if len(option) == 2 and arg.startswith("-") and not arg.startswith("--"):
        return option[1] in arg[1:]
    return False


def _escapes(value: str, root: Path, cwd: Path) -> bool:
    if value == "~" or value.startswith("~/"):
        return True
    path = Path(value)
    try:
        if not (path.is_absolute() or ".." in path.parts or (cwd / path).is_symlink()):
            return False
        (cwd / path).resolve().relative_to(root)
    except (OSError, ValueError):
        return True
    return False


def refusal(parts: list[str], *, root: Path, cwd: Path) -> str | None:
    """Why ``parts`` may not run, or ``None`` when its arguments are acceptable."""
    name = _name(parts[0])
    if name in _WRAPPERS:
        return f"'{parts[0]}' runs other programs and is refused"
    denied = _DENIED.get(name, ())
    for arg in parts[1:]:
        option = next((opt for opt in denied if _matches(arg, opt)), None)
        if option:
            return f"'{parts[0]} {option}' is refused"
        if name == "sed" and not arg.startswith("-") and _SED_EXEC.search(arg):
            return f"sed script {arg!r} executes or writes files and is refused"
        flagged = arg.startswith("-")
        if flagged and "=" not in arg:
            continue
        value = arg.split("=", 1)[1] if flagged else arg
        if _escapes(value, root, cwd):
            return f"argument {arg!r} escapes shell policy root {root}"
    return None
