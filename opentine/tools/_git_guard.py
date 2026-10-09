"""Running git where a model can write files: what makes it execute commands.

git executes programs named in its configuration -- ``core.fsmonitor``, a
``filter.*.clean`` driver, an alias starting with ``!`` -- and in several of its
own options. Allowlisting the ``git`` executable therefore bounded nothing: a
model could write ``.git/config`` with the fs tool, or pass ``-c alias.x=!cmd``
to the shell tool, and the next git invocation -- the model's own, or
``code_manifest`` capturing the workspace after the run -- ran its command on
the host (audit 0.9.1, D-1/D-3).

Three layers, each closing a different door:

* the fs tool refuses to write inside any ``.git`` (``tools.fs``), so a model
  cannot plant repository configuration or hooks;
* every git OpenTine starts runs with :data:`HARDENED_CONFIG`, which disables
  fsmonitor and refuses an *implicitly discovered* bare repository -- a
  directory of ``HEAD``/``config``/``objects``/``refs`` the model wrote with
  ordinary file writes;
* the shell tool refuses git options and subcommands that run a command, point
  git at another repository or configuration, or rewrite configuration
  (:func:`refusal`).

An allowlisted interpreter or test runner (``python``, ``pytest``, ``npm``) is
arbitrary code execution by design; the allowlist decides which program starts,
and only git's arguments are checked.
"""

from __future__ import annotations

from pathlib import PurePath

#: Prepended to every git command line OpenTine starts. An empty
#: ``core.fsmonitor`` reads as "off" on every git version (a boolean since 2.36,
#: a hook path before it); ``safe.bareRepository`` is ignored by git < 2.38.
HARDENED_CONFIG = ("-c", "core.fsmonitor=", "-c", "safe.bareRepository=explicit")

#: The global options (before the subcommand) the shell tool passes through. An
#: allowlist, because several others take a *separate* value (``--attr-source
#: HEAD``) that a denylist would read as the subcommand, letting the real one
#: through unchecked; and ``-c``/``--config-env``/``--exec-path=``/``--git-dir``
#: inject configuration or point git at other programs or another repository.
_GLOBAL_ALLOWED = frozenset(
    {
        "--no-pager",
        "-P",
        "-p",
        "--paginate",
        "--no-replace-objects",
        "--literal-pathspecs",
        "--glob-pathspecs",
        "--noglob-pathspecs",
        "--icase-pathspecs",
        "--no-optional-locks",
        "--version",
        "-v",
        "--help",
        "-h",
        "--exec-path",
    }
)

#: Subcommands whose purpose includes running a command, or that rewrite
#: configuration the next git invocation would then execute.
_SUBCOMMANDS_REFUSED = frozenset(
    {
        "config",
        "submodule",
        "filter-branch",
        "bisect",
        "difftool",
        "mergetool",
        "send-email",
        "instaweb",
        "daemon",
        "web--browse",
        "credential",
        "hook",
        "upload-pack",
        "receive-pack",
        "shell",
        "remote-ext",
        "remote-fd",
    }
)

#: Options that name a program to run (or a template/config to install).
_OPTIONS_REFUSED: dict[str, tuple[str, ...]] = {
    "*": ("--upload-pack", "--receive-pack", "--exec", "--ext-diff", "--open-files-in-pager"),
    "clone": ("-u", "-c", "--config", "--template", "--separate-git-dir"),
    "init": ("--template", "--separate-git-dir"),
    "ls-remote": ("-u",),
    "rebase": ("-x",),
    "grep": ("-O",),
    "archive": ("--remote",),
}


def is_git(executable: str) -> bool:
    return PurePath(executable).name.lower() in {"git", "git.exe"}


def _matches(token: str, option: str) -> bool:
    if option.startswith("--"):
        return token == option or token.startswith(option + "=")
    # A short option can be bundled (``-qc``) or take its value attached
    # (``-xcmd``), so its letter anywhere in a short-option cluster counts.
    return token.startswith("-") and not token.startswith("--") and option[1] in token[1:]


def refusal(arguments: list[str]) -> str | None:
    """Why git must not run with *arguments* (everything after ``git``), or None."""
    index = 0
    while index < len(arguments) and arguments[index].startswith("-"):
        token = arguments[index]
        if token == "-C" and index + 1 < len(arguments):
            index += 2  # -C takes its directory as the next argument
            continue
        if token not in _GLOBAL_ALLOWED:
            return f"git option {token.split('=', 1)[0]!r} is not allowed before the subcommand"
        index += 1
    if index == len(arguments):
        return None
    subcommand, rest = arguments[index], arguments[index + 1 :]
    if subcommand in _SUBCOMMANDS_REFUSED:
        return f"git {subcommand} is not allowed: it can run commands or rewrite configuration"
    refused = (*_OPTIONS_REFUSED["*"], *_OPTIONS_REFUSED.get(subcommand, ()))
    for token in rest:
        if token == "--":
            break
        if any(_matches(token, option) for option in refused):
            return f"git {subcommand} option {token.split('=', 1)[0]!r} is not allowed"
    return None


def hardened(parts: list[str]) -> list[str]:
    """*parts* (a git command line) with :data:`HARDENED_CONFIG` in front."""
    return [parts[0], *HARDENED_CONFIG, *parts[1:]]
