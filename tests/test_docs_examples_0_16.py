"""Every ``tine ...`` example in README.md and docs/*.md must parse (0.16 "Simplify").

Extraction rules (kept explicit so a failure is easy to read):

* Only lines inside fenced code blocks (````` ``` `````) are considered.
* A leading ``$ `` prompt and leading ``VAR=value`` environment assignments are dropped;
  the line must then start with the word ``tine``.
* Backslash line continuations are joined.
* A shell comment (`` #`` outside quotes) ends the command, and so does a run of two or
  more spaces (the description column of a ``command   what it does`` listing).
* For a pipeline / list (``|``, ``&&``, ``||``, ``;``) or a redirect (``>``, ``<``, ``2>``),
  only the first ``tine`` command is checked, up to that operator.
* ``<PLACEHOLDER>`` words and ``$VAR`` words are replaced by a dummy value. Synopsis
  notation is reduced to its required form: `` [optional]`` groups are dropped, an
  unspaced ``a|b`` word or a ``(a | b)`` group keeps its first alternative, and `` / ``
  ends the command.
  Lines containing ``...`` (an elided example) are skipped.
* ``KNOWN_NON_PARSING`` lists exact examples that are intentionally not parseable
  (e.g. showing an error). Keep it small and say why for each.

Each example goes through :func:`opentine.cli.parse`, the same alias/group expansion
and argparse parse ``tine`` itself runs, without dispatching anything.
"""

from __future__ import annotations

import contextlib
import io
import re
import shlex
from pathlib import Path

import pytest

from opentine.cli import parse

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]

# Exact (normalised) commands that are documented on purpose but do not parse.
KNOWN_NON_PARSING: dict[str, str] = {}

_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*$")
_PLACEHOLDER = re.compile(r"<[^<>\s]+>")
_CHOICE = re.compile(r"\(([^()|]*?)\s*\|[^()]*\)")
_OPTIONAL = re.compile(r"\s\[[^\[\]]*\]")
_STOP = {"|", "||", "&&", ";", "&", ">", ">>", "<", "2>", "2>&1", "1>", "&>"}


def _tokens(line: str) -> list[str] | None:
    line = _PLACEHOLDER.sub("x", line)  # <run>, <run|agt_ref> -> x
    line = re.split(r"\s/\s", line)[0]  # `tine reflog [ref] / tine reset ...` listings
    line = _CHOICE.sub(r"\1", line)  # `(--claim JSON | --claim-file PATH)` -> first
    while _OPTIONAL.search(line):  # synopsis `[--json]`: check the required form
        line = _OPTIONAL.sub("", line)
    try:
        words = shlex.split(line, comments=True)
    except ValueError:
        return None
    while words and _ENV.match(words[0]):
        words.pop(0)
    if not words or words[0] != "tine":
        return None
    out: list[str] = []
    for w in words[1:]:
        if w in _STOP or re.match(r"\d?>|&>|<", w):
            break
        if w.startswith("$"):
            w = "x"
        elif "|" in w and not w.startswith(("{", "-")) and " " not in w:
            w = w.split("|")[0]  # synopsis alternatives: `status|stop|cost`
        out.append(w)
    return out


def _examples() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for doc in DOCS:
        fenced = False
        pending = ""
        for n, raw in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            if raw.lstrip().startswith("```"):
                fenced, pending = not fenced, ""
                continue
            if not fenced:
                continue
            line = pending + re.split(r"\s{2,}", raw.strip())[0]
            if line.endswith("\\"):
                pending = line[:-1] + " "
                continue
            pending = ""
            if line.startswith("$ "):
                line = line[2:]
            if "..." in line or "…" in line:
                continue
            if "tine" not in line.split("#")[0].split():
                continue
            found.append((f"{doc.relative_to(ROOT)}:{n}", line))
    return found


EXAMPLES = _examples()


def test_examples_were_found():
    assert len(EXAMPLES) > 50


@pytest.mark.parametrize(("where", "line"), EXAMPLES, ids=[w for w, _ in EXAMPLES])
def test_doc_example_parses(where, line):
    argv = _tokens(line)
    if argv is None:
        pytest.skip("not a plain tine command")
    if " ".join(argv) in KNOWN_NON_PARSING:
        pytest.skip(KNOWN_NON_PARSING[" ".join(argv)])
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            parse(argv)
    except SystemExit as exc:
        if exc.code not in (0, None):  # --help / --version exit 0
            pytest.fail(f"{where}: `tine {' '.join(argv)}` does not parse:\n{err.getvalue()}")
