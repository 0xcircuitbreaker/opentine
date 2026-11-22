"""The toy repository the loop improves: a string-operation solver.

A task is ``"OP:ARG"`` and its answer is the operation applied to ``ARG``. The
solver (``solver.py``) knows a set of operations; an unknown one returns
``ARG`` unchanged. Three item sets are fixed and deterministic:

* ``visible``: the tasks the loop may see (``tests/visible.jsonl``);
* ``holdout``: other arguments, sealed with ``tine dataset seal``;
* ``canary``: three rounds in seven have an empty argument; checked after promotion.

Variants run in a child process (``python -I``, empty environment) inside
their own sandbox folder, never in the loop's process: a proposed solver is
untrusted code. Before the solver's code runs, the child installs an audit hook
that refuses every audited operation (opening files, ``os``, ``subprocess``,
sockets, imports, ``ctypes``, new hooks), so a variant cannot read keys, the
released holdout or anything else on disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

OPS = {
    "upper": ("lambda s: s.upper()", lambda s: s.upper()),
    "reverse": ("lambda s: s[::-1]", lambda s: s[::-1]),
    "length": ("lambda s: str(len(s))", lambda s: str(len(s))),
    "sort": ("lambda s: ''.join(sorted(s))", lambda s: "".join(sorted(s))),
    "double": ("lambda s: s + s", lambda s: s + s),
    "vowels": ("lambda s: str(sum(c in 'aeiou' for c in s))",
               lambda s: str(sum(c in "aeiou" for c in s))),
}  # fmt: skip
ORDER = tuple(OPS)
WORDS = ("amber", "basil", "cedar", "delta", "ember", "fjord", "gamma", "heron", "indigo",
         "juniper", "kestrel", "lumen", "maple", "nectar", "onyx", "pebble", "quartz", "raven",
         "sable", "tundra", "umber")  # fmt: skip
#: Minutes a person needs per operation (the uplift suite's task lengths).
MINUTES = {"upper": "1", "reverse": "2", "length": "2", "sort": "4", "double": "4",
           "vowels": "8"}  # fmt: skip

_RUNNER = """
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    code = compile(handle.read(), "solver.py", "exec")
feed = json.loads(sys.stdin.read())
first = [True]
def deny(event, args):
    if event == "exec" and first[0]:
        first[0] = False
        return
    raise PermissionError("contained: " + event)
sys.addaudithook(deny)
scope = {"__name__": "solver"}
exec(code, scope)
out = {}
for item in feed:
    try:
        out[item["id"]] = str(scope["solve"](item["input"]))
    except BaseException as exc:
        out[item["id"]] = "error: " + type(exc).__name__
sys.stdout.write(json.dumps(out, sort_keys=True))
"""


def _item(prefix: str, n: int, op: str, arg: str) -> dict[str, str]:
    return {"id": f"{prefix}-{n:03d}", "input": f"{op}:{arg}", "expected": OPS[op][1](arg)}


def items(kind: str) -> list[dict[str, str]]:
    """The fixed ``visible``, ``holdout`` or ``canary`` items (42 each)."""
    out = []
    for n in range(42):
        op = ORDER[n % len(ORDER)]
        word = WORDS[n // len(ORDER) + (7 if kind == "holdout" else 0)]
        if kind == "canary":
            word = "" if (n // len(ORDER)) % 2 else WORDS[(n * 5) % len(WORDS)][::-1]
        out.append(_item(kind, n, op, word))
    return out


def source(ops: list[str], *, answers: dict[str, str] | None = None,
           empty_shortcut: bool = False) -> str:  # fmt: skip
    """The text of a ``solver.py`` that knows *ops* (sorted for a stable digest)."""
    lines = ['"""Solve OP:ARG tasks (a variant of the reference loop)."""', "", "IMPL = {"]
    lines += [f"    {op!r}: {OPS[op][0]}," for op in ORDER if op in ops]
    lines += ["}", ""]
    if answers:
        lines += ["ANSWERS = " + json.dumps(answers, sort_keys=True), ""]
    lines += ["", "def solve(text):", '    op, _, arg = text.partition(":")']
    if answers:
        lines += ["    if text in ANSWERS:", "        return ANSWERS[text]"]
    if empty_shortcut:
        lines += ["    if not arg:", '        return "?"']
    lines += ["    fn = IMPL.get(op)", "    return fn(arg) if fn else arg", ""]
    return "\n".join(lines)


def digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _env() -> dict[str, str]:
    """No inherited variables (no keys, no paths); Windows needs SYSTEMROOT to start."""
    return {k: os.environ[k] for k in ("SYSTEMROOT",) if k in os.environ}


def run_solver(sandbox: Path, solver: str, tasks: list[dict[str, str]]) -> dict[str, str]:
    """Each task's output from *solver* run in a child process in *sandbox*."""
    sandbox.mkdir(parents=True, exist_ok=True)
    path = sandbox / "solver.py"
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(solver)
    feed = json.dumps([{"id": t["id"], "input": t["input"]} for t in tasks]).encode("utf-8")
    argv = [sys.executable, "-I", "-c", _RUNNER, path.name]
    done = subprocess.run(argv, input=feed, cwd=sandbox, env=_env(), capture_output=True,
                          timeout=120, check=False)  # fmt: skip
    if done.returncode != 0:
        return {t["id"]: "error: crashed" for t in tasks}
    return json.loads(done.stdout.decode("utf-8"))


def write_repo(root: Path) -> None:
    """The toy repository's protected files: grader, visible tests, sandbox policy."""
    files = {
        "grader/check.py": '"""Exact-match grader."""\n\n\ndef passed(output, expected):\n'
        "    return output == expected\n",
        "tests/visible.jsonl": "".join(
            json.dumps(i, sort_keys=True) + "\n" for i in items("visible")
        ),  # fmt: skip
        "sandbox.json": json.dumps({"network": "none", "mounts": ["sandbox/"]}) + "\n",
    }
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)


__all__ = ["MINUTES", "OPS", "ORDER", "digest", "items", "run_solver", "source", "write_repo"]
