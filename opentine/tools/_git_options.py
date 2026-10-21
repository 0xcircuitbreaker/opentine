"""Option tables for :mod:`opentine.tools._git_policy`: values, paths and opt-ins."""

from __future__ import annotations


def _w(text: str) -> frozenset[str]:
    return frozenset(text.split())


def _spec(long: frozenset[str], short: str) -> tuple[frozenset[str], str]:
    return long, short


#: Long options that take their value as the *next* argument unless given
#: as ``--name=value``; everything else is a flag.
VALUE_LONG = _w(
    "--after --author --before --cleanup --committer --contains --date --depth "
    "--diff-filter --dst-prefix --file --fixup --format --grep --initial-branch "
    "--max-count --max-depth --merged --message --no-merged --origin --output "
    "--output-directory --pathspec-from-file --points-at --prefix --push-option "
    "--repo --set-upstream-to --shallow-since --since --skip --sort --src-prefix "
    "--strategy --strategy-option --until --word-diff-regex"
)
#: Long options whose value is optional and only ever attached (``=value``),
#: so a following token is never swallowed as their value.
OPTIONAL_VALUE_LONG = _w(
    "--abbrev --color --decorate --dirstat --find-copies --find-renames "
    "--force-with-lease --ignore-submodules --porcelain --pretty --recurse-submodules "
    "--relative --track --unified --untracked-files --word-diff"
)
#: Long options that take a value only for one subcommand (a flag elsewhere).
VALUE_LONG_FOR = {
    "checkout": _w("--orphan"),
    "clone": _w("--branch"),
    "commit": _w("--squash"),
    "restore": _w("--source"),
    "shortlog": _w("--group"),
    "switch": _w("--create --force-create --orphan"),
}
#: Short options whose value is the rest of the token or the next argument.
VALUE_SHORT = {
    "commit": "mFCc",
    "tag": "mFu",
    "merge": "msX",
    "log": "nSG",
    "show": "nSG",
    "reflog": "n",
    "restore": "s",
    "init": "b",
    "grep": "efmABC",
    "branch": "u",
    "checkout": "bB",
    "switch": "cC",
    "stash": "m",
    "clone": "bo",
    "fetch": "",
    "pull": "sX",
    "push": "o",
    "worktree": "b",
    "blame": "L",
    "archive": "o",
    "format-patch": "o",
}

#: Short options whose value is optional and only ever attached (``-U5``,
#: ``-uno``): a following token is never their value.
OPTIONAL_VALUE_SHORT = {
    "blame": "MC",
    "branch": "t",
    "diff": "UMCB",
    "log": "UMCB",
    "show": "UMCB",
    "status": "u",
}

#: Path-valued options per subcommand: their value must resolve inside the root.
PATH_OPTIONS: dict[str, frozenset[str]] = {
    "commit": _w("--file -F"),
    "tag": _w("--file -F"),
    "grep": _w("-f"),
    "archive": _w("--output -o"),
    "format-patch": _w("--output-directory -o"),
}

#: A merge strategy names a ``git-merge-<name>`` program found on ``PATH``, so
#: only git's own strategies are accepted.
STRATEGIES = _w("octopus ort ours recursive resolve subtree")

#: Data leaves or enters the machine: only with ``ShellPolicy.git_network``.
NETWORK: dict[str, tuple[frozenset[str], str]] = {
    "fetch": _spec(
        _w(
            "--all --depth --dry-run --force --no-tags --prune --quiet --shallow-since --tags "
            "--unshallow"
        ),
        "aptqnf",
    ),
    "pull": _spec(
        _w(
            "--depth --ff-only --no-ff --no-rebase --prune --quiet --rebase --strategy "
            "--strategy-option --tags"
        ),
        "rqpsX",
    ),
    "push": _spec(
        _w(
            "--atomic --delete --dry-run --follow-tags --force --force-with-lease --no-verify "
            "--push-option --quiet --set-upstream --tags"
        ),
        "ufnqdo",
    ),
    "ls-remote": _spec(
        _w("--heads --quiet --refs --symref --tags"),
        "htq",
    ),
}

#: git writes files where the fs tool cannot see: only with ``git_write_out``,
#: and every path they write must resolve inside the shell root.
WRITE_OUT: dict[str, tuple[frozenset[str], str]] = {
    "init": _spec(
        _w("--bare --initial-branch --quiet"),
        "qb",
    ),
    "clone": _spec(
        _w(
            "--branch --depth --no-checkout --no-tags --origin --quiet --shallow-since "
            "--single-branch"
        ),
        "qnbo",
    ),
    "archive": _spec(
        _w("--format --output --prefix"),
        "o",
    ),
    "format-patch": _spec(
        _w("--numbered --output-directory --stdout"),
        "on",
    ),
}

#: Global options before the subcommand. ``-C`` is handled (and contained)
#: separately; ``-p``/``--paginate`` are gone -- they launched a pager.
GLOBAL_ALLOWED = _w(
    "--glob-pathspecs --icase-pathspecs --literal-pathspecs --no-optional-locks "
    "--no-pager --no-replace-objects --noglob-pathspecs --version -P"
)

#: Subcommands whose positional arguments are local paths git will write.
POSITIONAL_PATHS = _w("clone init")
