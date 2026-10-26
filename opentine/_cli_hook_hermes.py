"""``tine hook install --agent hermes``: a snippet for Hermes Agent, never an edit.

Hermes Agent documents shell hooks as a ``hooks:`` block in
``$HERMES_HOME/config.yaml`` (default ``~/.hermes``): ``<event>: [{command,
timeout}]``, each command split with ``shlex`` and run without a shell, every
new ``(event, command)`` pair approved once by the user
(hermes-agent.nousresearch.com/docs/user-guide/features/hooks). Rewriting a
user's YAML safely needs a round-tripping YAML parser opentine does not ship,
so install and uninstall only **print** the block to paste or remove; status
looks for opentine's command in the file's text, without parsing it.

The hook imports ``trajectory_samples.jsonl`` from the directory Hermes runs
in -- where Hermes writes trajectories when they are enabled -- as
``--format hermes-trajectory`` (the newest record).
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

from opentine._cli_common import _terminal, console

MAX_CONFIG_BYTES = 1024 * 1024
EVENT = "on_session_end"
TRAJECTORY = "trajectory_samples.jsonl"


def config_path() -> Path:
    value = os.environ.get("HERMES_HOME")
    return (Path(value).expanduser() if value else Path.home() / ".hermes") / "config.yaml"


def command(repo: Path) -> str:
    argv = [sys.executable, "-I", "-m", "opentine.cli", "import", TRAJECTORY,
            "--format", "hermes-trajectory", "--repo", str(repo)]  # fmt: skip
    if os.name == "nt":  # shlex.split eats backslashes; Windows accepts forward slashes
        argv = [part.replace("\\", "/") for part in argv]
    return shlex.join(argv)


def snippet(repo: Path) -> str:
    # A JSON string is a valid YAML double-quoted scalar: no quoting surprises.
    return f"hooks:\n  {EVENT}:\n    - command: {json.dumps(command(repo))}\n      timeout: 120\n"


def installed() -> bool:
    path = config_path()
    try:
        if path.is_symlink() or not path.is_file():
            return False
        with open(path, "rb") as handle:
            text = handle.read(MAX_CONFIG_BYTES).decode("utf-8", "replace")
    except OSError:
        return False
    return "opentine.cli" in text and "hermes-trajectory" in text


def hermes(action: str, repo: Path | None) -> None:
    path = config_path()
    if action == "status":
        state = f"{EVENT} (snippet)" if installed() else "not installed"
        console.print(f"  {'hermes':<12} {state:<30} {_terminal(path)}", markup=False)
        return
    if action == "uninstall":
        console.print(f"  hermes       remove opentine's {EVENT} entry from {_terminal(path)}")
        return
    assert repo is not None
    console.print(
        f"  hermes       not edited: add this to {_terminal(path)} "
        "(Hermes asks you to approve it on first use):",
        markup=False,
    )
    console.print(snippet(repo), markup=False)


__all__ = ["EVENT", "command", "config_path", "hermes", "installed", "snippet"]
