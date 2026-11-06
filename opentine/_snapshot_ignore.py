""".gitignore-style rules for per-turn snapshots (SPEC "Tree blobs").

Rules come from the caller's ``ignore`` patterns (relative to the snapshot
root), every ``.gitignore`` met on the walk (relative to its directory), and the
exclude globs of the root ``.tineignore``. Git's semantics are kept where they
matter for a snapshot: ``!`` re-includes, a trailing ``/`` matches directories
only, a pattern with an inner ``/`` is anchored, ``**`` spans directories, the
last matching rule wins, and nothing under an excluded directory is visited.
Version-control directories (``.git``, ``.tine``, ...) are always left out.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ALWAYS = frozenset({".git", ".tine", ".hg", ".svn", ".bzr", "_darcs", ".jj", ".pijul"})
MAX_RULE_FILE = 256 * 1024


@dataclass(frozen=True)
class Rule:
    base: str  # directory the rule is relative to ("" for the root), "/"-terminated
    regex: re.Pattern[str]
    negate: bool
    dir_only: bool


def _translate(pattern: str) -> str:
    out, i = [], 0
    while i < len(pattern):
        char = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[" and (end := pattern.find("]", i + 2)) != -1:
            body = pattern[i + 1 : end]
            body = "^" + body[1:] if body[:1] == "!" else body
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = end
        elif char == "\\" and i + 1 < len(pattern):
            i += 1
            out.append(re.escape(pattern[i]))
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)


def compile_rule(line: str, base: str = "") -> Rule | None:
    line = line.rstrip("\r\n")
    if not line.endswith("\\ "):
        line = line.rstrip(" ")
    if not line or line.startswith("#"):
        return None
    negate = line.startswith("!")
    line = line[1:] if negate else line.removeprefix("\\")
    dir_only = line.endswith("/")
    line = line.rstrip("/")
    if not line:
        return None
    anchored = "/" in line
    body = _translate(line.lstrip("/"))
    try:
        regex = re.compile(("" if anchored else "(?:.*/)?") + body + r"\Z", re.DOTALL)
    except re.error:
        return None
    return Rule(base, regex, negate, dir_only)


def parse_rules(text: str, base: str = "") -> list[Rule]:
    return [rule for line in text.splitlines() if (rule := compile_rule(line, base))]


def read_rules(directory: Path, base: str) -> list[Rule]:
    path = directory / ".gitignore"
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RULE_FILE:
            return []
        return parse_rules(path.read_text(encoding="utf-8", errors="replace"), base)
    except OSError:
        return []


def root_rules(root: Path, ignore: Iterable[str] = ()) -> list[Rule]:
    from opentine._tineignore import load

    rules = [rule for line in ignore if (rule := compile_rule(line))]
    for glob in load(root).exclude:  # a malformed .tineignore is an error, as for capture
        rule = compile_rule("/" + glob)
        rules.extend([rule] if rule else [])
    return rules


def ignored(rules: list[Rule], path: str, is_dir: bool) -> bool:
    """Whether the root-relative POSIX *path* is ignored (last match wins)."""
    if path.rsplit("/", 1)[-1] in ALWAYS:
        return True
    verdict = False
    for rule in rules:
        if rule.dir_only and not is_dir:
            continue
        if rule.base and not path.startswith(rule.base):
            continue
        if rule.regex.match(path[len(rule.base) :]):
            verdict = not rule.negate
    return verdict


__all__ = ["ALWAYS", "Rule", "compile_rule", "ignored", "parse_rules", "read_rules", "root_rules"]
