"""Files a shell command line writes or deletes (see :mod:`opentine._actions`).

A shell step is ``exec``, but ``echo x > f``, ``cp a f``, ``sed -i ... f`` or
``dd of=f`` change files as surely as a Write tool does. Without this,
``tine touched`` and ``writes=true`` policy rules would report that nobody
wrote a file an agent changed through its shell. The parse is heuristic and
bounded: one pass over the tokens of each ``&&``/``;``/``|`` segment.
"""

from __future__ import annotations

from opentine._actions_parse import _OPERATORS, _program, _tokens

_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>"})
_DEVICES = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"})
_LAST_OPERAND = frozenset({"cp", "mv", "install", "ln", "rsync", "scp"})
_ALL_OPERANDS = frozenset({"tee", "touch", "truncate"})
#: Every operand is deleted (``rm notes.txt`` names a bare file, no slash).
_DELETERS = frozenset({"rm", "rmdir", "unlink", "shred"})
_AFTER_MODE = frozenset({"chmod", "chown", "chgrp"})
#: Options that take the next token as their value, per program (``rm -r`` does not).
_VALUE_FLAGS = {
    "truncate": frozenset({"-s", "--size", "-r", "--reference"}),
    "install": frozenset({"-m", "--mode", "-o", "--owner", "-g", "--group"}),
    "chmod": frozenset({"--reference"}),
    "chown": frozenset({"--reference"}),
    "chgrp": frozenset({"--reference"}),
    "shred": frozenset({"-n", "--iterations", "-s", "--size"}),
    "sed": frozenset({"-e", "--expression", "-f", "--file"}),
}
MAX_WRITES = 64


def _operands(segment: list[str], program: str) -> tuple[list[str], str]:
    """Non-option operands after *program* in *segment*, and any ``-t DIR`` target."""
    start = next(
        (i + 1 for i, token in enumerate(segment) if token.rsplit("/", 1)[-1] == program),
        len(segment),
    )
    operands: list[str] = []
    target, index = "", start
    while index < len(segment):
        token = segment[index]
        index += 1
        if token in ("-t", "--target-directory") and index < len(segment):
            target, index = segment[index], index + 1
        elif token.startswith("--target-directory="):
            target = token.split("=", 1)[1]
        elif token in _VALUE_FLAGS.get(program, ()):
            index += 1
        elif not token.startswith("-") or token == "-":
            operands.append(token)
    return operands, target


def _segment_writes(segment: list[str], deletes: bool = False) -> list[str]:
    found: list[str] = []
    plain: list[str] = []
    index = 0
    while index < len(segment):
        token = segment[index]
        if token in _REDIRECTS and index + 1 < len(segment):
            if not segment[index + 1].startswith("&"):
                found.append(segment[index + 1])
            index += 2
            continue
        plain.append(token)
        index += 1
    program = _program(plain) if plain else ""
    operands, target = _operands(plain, program) if program else ([], "")
    if deletes:
        return operands if program in _DELETERS else []
    if target:
        found.append(target)
    if program in _LAST_OPERAND and len(operands) >= 2 and not target:
        found.append(operands[-1])
    elif program in _ALL_OPERANDS:
        found.extend(operands)
    elif program in _AFTER_MODE:
        found.extend(operands[1:])
    elif program == "sed" and any(t.startswith(("-i", "--in-place")) for t in plain):
        # Without -e/-f the first operand is the script, not a file.
        scripted = any(t.split("=", 1)[0] in _VALUE_FLAGS["sed"] for t in plain)
        found.extend(operands if scripted else operands[1:])
    elif program == "dd":
        found.extend(t[3:] for t in plain if t.startswith("of="))
    return found


def written_paths(command: str, *, deletes: bool = False) -> list[str]:
    """Paths *command* writes through redirects and common file-writing programs.

    With *deletes*, the operands of ``rm``/``rmdir``/``unlink``/``shred`` instead.
    """
    found: dict[str, None] = {}
    segment: list[str] = []
    for token in [*_tokens(command), ";"]:
        if token in _OPERATORS:
            for path in _segment_writes(segment, deletes):
                cleaned = path.strip().strip("'\"")
                if cleaned and cleaned not in _DEVICES and "\n" not in cleaned:
                    found.setdefault(cleaned, None)
            segment = []
            if len(found) >= MAX_WRITES:
                break
        else:
            segment.append(token)
    return list(found)[:MAX_WRITES]


__all__ = ["written_paths"]
