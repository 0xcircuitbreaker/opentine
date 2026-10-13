"""Refuse arguments cmd.exe would re-parse when Windows runs a batch file.

``CreateProcess`` runs a ``.bat``/``.cmd`` program through ``cmd.exe``, which
parses the whole command line again with its own rules. Python quotes argv for
the C runtime, not for cmd (the BatBadBut class, CVE-2024-24576), so an argument
holding ``"`` and ``&`` closes the quoted string and cmd runs the rest as a
command. Untrusted text reaches argv in two places -- a harness's task and the
shell tool's model-chosen arguments -- and npm installs most agent CLIs as
``.cmd`` shims. Such a launch is refused unless no argument holds a character
cmd treats specially; the real entry point (``node <path>\\cli.js``, an ``.exe``)
takes any argument safely.
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from pathlib import PureWindowsPath

_BATCH_SUFFIXES = (".bat", ".cmd")
#: Quote, variable expansion (%, and ! under delayed expansion), escape,
#: command separators and redirections, and line breaks.
_CMD_SPECIAL = re.compile(r'["%!^&|<>\r\n]')


def is_batch_file(program: str) -> bool:
    # Windows ignores trailing dots and spaces in a file name: "x.cmd. " is x.cmd.
    name = PureWindowsPath(str(program).rstrip(". ")).name.lower()
    return name.endswith(_BATCH_SUFFIXES)


def batch_refusal(argv: Sequence[str], *, os_name: str | None = None) -> str | None:
    """Why *argv* cannot be launched safely, or ``None`` when it can."""
    if (os_name or os.name) != "nt" or not argv or not is_batch_file(argv[0]):
        return None
    for argument in argv[1:]:
        if _CMD_SPECIAL.search(str(argument)):
            return (
                f"{argv[0]!r} is a batch file, which cmd.exe re-parses: an argument holding "
                '" % ! ^ & | < > or a line break could run a command. Launch the real '
                "executable instead (for an npm CLI, node and its JavaScript entry point)"
            )
    return None


def refuse_batch_injection(argv: Sequence[str], *, os_name: str | None = None) -> None:
    reason = batch_refusal(argv, os_name=os_name)
    if reason is not None:
        raise ValueError(reason)
