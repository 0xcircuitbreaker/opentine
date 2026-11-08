"""Run the CI gate from environment variables (0.46: ``actions/gate`` and GitLab).

``python -m opentine._ci_run`` is the one entry point both CI integrations
call. Inputs arrive as environment variables -- never as script text a CI
template interpolated, so an input cannot inject a command:

* ``RUNS``, ``EVAL_DIRS``: newline-separated paths;
* ``PUBKEY``, ``EVAL_PUBKEY``, ``VSA``, ``VSA_KEY``, ``SUBJECT``, ``VSA_POLICY``;
* ``VSA_LEVELS``: space-separated; ``OUT``: the output folder (``opentine-gate``).

It runs ``tine verify RUN --json`` and ``tine eval verify DIR --json`` for each
path (arguments as a list, no shell), keeps their JSON in ``OUT``, then
decides with :mod:`opentine._ci_gate`. Exit codes are the gate's; on GitHub it
also writes the ``ok`` and ``summary`` step outputs.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from opentine import _ci_gate

_TINE = (sys.executable, "-c", "import sys; from opentine.cli import main; sys.exit(main())")


def _lines(value: str) -> list[str]:
    # A path is never an option: "-x" is passed as "./-x".
    return [
        ("./" if s.startswith("-") else "") + s
        for s in (x.strip() for x in value.splitlines())
        if s
    ]


def _tine(env: Mapping[str, str]) -> list[str]:
    custom = env.get("OPENTINE_TINE", "")
    return shlex.split(custom) if custom else list(_TINE)


def _capture(command: list[str], target: Path) -> None:
    with target.open("wb") as handle:
        subprocess.run(command, stdout=handle, stderr=subprocess.DEVNULL, check=False,
                       timeout=600)  # fmt: skip


def gate_args(env: Mapping[str, str]) -> list[str]:
    """Run the tools and return the ``_ci_gate`` arguments for their outputs."""
    out = Path(env.get("OUT") or "opentine-gate")
    out.mkdir(parents=True, exist_ok=True)
    args = ["--summary", str(out / "summary.json"), "--comment", str(out / "comment.md")]
    tine, index = _tine(env), 0
    jobs = (
        ("verify", "RUNS", "PUBKEY", "--verify"),
        ("eval verify", "EVAL_DIRS", "EVAL_PUBKEY", "--eval"),
    )
    for verb, var, key, flag in jobs:
        for path in _lines(env.get(var, "")):
            index += 1
            target = out / f"{verb.split()[0]}-{index}.json"
            pubkey = ["--pubkey", env[key]] if env.get(key) else []
            _capture([*tine, *verb.split(), path, *pubkey, "--json"], target)
            args += [flag, str(target)]
    if env.get("VSA"):
        args += ["--vsa", env["VSA"], "--vsa-key", env.get("VSA_KEY", ""),
                 "--subject", env.get("SUBJECT", "")]  # fmt: skip
        if env.get("VSA_POLICY"):
            args += ["--vsa-policy", env["VSA_POLICY"]]
        for level in env.get("VSA_LEVELS", "").split():
            args += ["--vsa-level", level]
    return args


def main(env: Mapping[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    args = gate_args(env)
    status = _ci_gate.main(args)
    output = env.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"ok={'true' if status == 0 else 'false'}\nsummary={args[1]}\n")
    return status


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
