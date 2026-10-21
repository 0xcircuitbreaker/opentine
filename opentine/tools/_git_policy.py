"""Which git subcommands and options the shell tool lets a model use.

An allowlist, read-mostly by default. A denylist of "options that run a
command" failed open twice: git accepts any unambiguous abbreviation of a long
option (``--upl`` is ``--upload-pack``), and its command set is open-ended
(``maintenance``, ``credential-store``, any ``git-*`` program on ``PATH``).
Here a subcommand runs only if it is listed, and a long option only if its
*exact* name is listed for that subcommand -- an abbreviation is never one.

Network subcommands (data leaves or enters the machine) and write-out
subcommands (git writes files where the fs tool's containment never looks) run
only when the shell policy opts in.
"""

from __future__ import annotations

from opentine.tools._git_options import (  # noqa: F401 - re-exported for the guard
    GLOBAL_ALLOWED,
    NETWORK,
    OPTIONAL_VALUE_LONG,
    OPTIONAL_VALUE_SHORT,
    PATH_OPTIONS,
    POSITIONAL_PATHS,
    STRATEGIES,
    VALUE_LONG,
    VALUE_LONG_FOR,
    VALUE_SHORT,
    WRITE_OUT,
    _spec,
    _w,
)

#: Read-mostly subcommands every shell policy that allows git may run.
SUBCOMMANDS: dict[str, tuple[frozenset[str], str]] = {
    "status": _spec(
        _w(
            "--ahead-behind --branch --column --ignore-submodules --ignored --long "
            "--no-ahead-behind --no-column --no-renames --porcelain --renames --short "
            "--show-stash --untracked-files"
        ),
        "sbuz",
    ),
    "log": _spec(
        _w(
            "--abbrev --after --all --all-match --ancestry-path --author --before --binary "
            "--boundary --branches --cached --check --cherry-pick --children --color --committer "
            "--compact-summary --count --date --date-order --decorate --diff-filter --dirstat "
            "--dst-prefix --exit-code --find-copies --find-renames --first-parent --follow "
            "--format --full-history --full-index --graph --grep --histogram --ignore-all-space "
            "--ignore-blank-lines --ignore-space-change --invert-grep --left-right --max-count "
            "--merge-base --merges --minimal --name-only --name-status --no-abbrev --no-color "
            "--no-decorate --no-ext-diff --no-merges --no-patch --no-prefix --no-relative "
            "--no-textconv --no-walk --numstat --oneline --parents --patch --patience --pretty "
            "--quiet --raw --regexp-ignore-case --relative --remotes --reverse --shortstat "
            "--show-signature --simplify-by-decoration --since --skip --source --src-prefix "
            "--staged --stat --summary --tags --text --topo-order --unified --until "
            "--walk-reflogs --word-diff --word-diff-regex"
        ),
        "puUwbMCRzqangiSGL",
    ),
    "show": _spec(
        _w(
            "--abbrev --after --all --all-match --ancestry-path --author --before --binary "
            "--boundary --branches --cached --check --cherry-pick --children --color --committer "
            "--compact-summary --count --date --date-order --decorate --diff-filter --dirstat "
            "--dst-prefix --exit-code --find-copies --find-renames --first-parent --follow "
            "--format --full-history --full-index --graph --grep --histogram --ignore-all-space "
            "--ignore-blank-lines --ignore-space-change --invert-grep --left-right --max-count "
            "--merge-base --merges --minimal --name-only --name-status --no-abbrev --no-color "
            "--no-decorate --no-ext-diff --no-merges --no-patch --no-prefix --no-relative "
            "--no-textconv --no-walk --numstat --oneline --parents --patch --patience --pretty "
            "--quiet --raw --regexp-ignore-case --relative --remotes --reverse --shortstat "
            "--show-signature --simplify-by-decoration --since --skip --source --src-prefix "
            "--staged --stat --summary --tags --text --topo-order --unified --until "
            "--walk-reflogs --word-diff --word-diff-regex"
        ),
        "puUwbMCRzqangiSGL",
    ),
    "diff": _spec(
        _w(
            "--abbrev --binary --cached --check --color --compact-summary --diff-filter --dirstat "
            "--dst-prefix --exit-code --find-copies --find-renames --full-index --histogram "
            "--ignore-all-space --ignore-blank-lines --ignore-space-change --merge-base --minimal "
            "--name-only --name-status --no-abbrev --no-color --no-ext-diff --no-patch "
            "--no-prefix --no-relative --no-textconv --numstat --patch --patience --quiet --raw "
            "--relative --shortstat --src-prefix --staged --stat --summary --text --unified "
            "--word-diff --word-diff-regex"
        ),
        "puUwbMCRzqa",
    ),
    "shortlog": _spec(
        _w("--all --email --group --numbered --summary"),
        "sne",
    ),
    "describe": _spec(
        _w("--abbrev --all --always --dirty --long --tags"),
        "",
    ),
    "add": _spec(
        _w(
            "--all --dry-run --force --ignore-errors --intent-to-add --no-all "
            "--renormalize --update --verbose"
        ),
        "uAnNvf",
    ),
    "rm": _spec(
        _w("--cached --dry-run --force --ignore-unmatch --quiet"),
        "rfqn",
    ),
    "mv": _spec(
        _w("--dry-run --force --verbose"),
        "fnkv",
    ),
    "commit": _spec(
        _w(
            "--all --allow-empty --allow-empty-message --amend --author --cleanup --date "
            "--dry-run --file --fixup --include --message --no-edit --no-verify --only "
            "--porcelain --quiet --reset-author --short --signoff --squash"
        ),
        "mFaqsnvC",
    ),
    "branch": _spec(
        _w(
            "--all --color --contains --copy --delete --force --list --merged --move --no-color "
            "--no-merged --no-track --points-at --remotes --set-upstream-to --show-current --sort "
            "--track --unset-upstream --verbose"
        ),
        "ardDmMcCfvtu",
    ),
    "checkout": _spec(
        _w("--detach --force --merge --no-track --orphan --ours --quiet --theirs --track"),
        "fqbBpm",
    ),
    "switch": _spec(
        _w(
            "--create --detach --discard-changes --force --force-create --merge --no-track "
            "--orphan --quiet --track"
        ),
        "cCdfqm",
    ),
    "restore": _spec(
        _w(
            "--merge --no-progress --ours --patch --progress --quiet --source --staged --theirs "
            "--worktree"
        ),
        "sSWpq",
    ),
    "rev-parse": _spec(
        _w(
            "--abbrev-ref --absolute-git-dir --all --git-dir --is-inside-work-tree --quiet "
            "--short --show-cdup --show-prefix --show-toplevel --symbolic-full-name --verify"
        ),
        "q",
    ),
    "ls-files": _spec(
        _w(
            "--cached --deleted --directory --error-unmatch --exclude-standard --full-name "
            "--ignored --modified --others --stage"
        ),
        "cdmoisz",
    ),
    "ls-tree": _spec(
        _w("--full-name --full-tree --name-only --name-status"),
        "rtdlz",
    ),
    "cat-file": _spec(
        _w("--batch-check"),
        "tsep",
    ),
    "grep": _spec(
        _w(
            "--all-match --and --break --cached --column --count --extended-regexp "
            "--files-with-matches --files-without-match --fixed-strings --full-name --heading "
            "--ignore-case --invert-match --line-number --max-depth --not --null --only-matching "
            "--or --perl-regexp --quiet --untracked --word-regexp"
        ),
        "iwnclLEFPvqohIzrefABC",
    ),
    "blame": _spec(
        _w("--date --line-porcelain --porcelain --reverse --root --show-email --show-name"),
        "lLsecwMC",
    ),
    "stash": _spec(
        _w("--all --include-untracked --index --keep-index --message --patch --quiet --staged"),
        "ukmqap",
    ),
    "tag": _spec(
        _w(
            "--annotate --contains --delete --force --list --merged --message --no-merged "
            "--points-at --sort --verify"
        ),
        "lamdfnv",
    ),
    "merge": _spec(
        _w(
            "--abort --allow-unrelated-histories --commit --continue --ff --ff-only --message "
            "--no-commit --no-edit --no-ff --no-stat --no-verify --quiet --squash --stat "
            "--strategy --strategy-option"
        ),
        "mqsXn",
    ),
    "reset": _spec(
        _w("--hard --keep --merge --mixed --quiet --soft"),
        "qp",
    ),
    "reflog": _spec(
        _w("--all --date"),
        "n",
    ),
    "version": _spec(
        _w(""),
        "",
    ),
}
