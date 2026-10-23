"""One verb set: plain ``show``/``diff``/``search``/``fork``/``tag`` reach the v3 repo.

Until 0.12 the v3 repository had its own ``repo-*`` spellings and the plain
verbs only read legacy ``.tine`` files. Now a plain verb acts on the v3
repository when one is found **and** its arguments name things in it (refs or
oids); otherwise it keeps its legacy meaning, so existing scripts are unchanged:

* ``--legacy`` always forces the file behaviour;
* an argument that is an existing path, or a run in the legacy runs directory,
  forces it too (``tine show runs/abc.tine`` and ``tine show abc123`` still work);
* ``tag --add/--remove/--list`` is the legacy label editor; ``tag NAME [RUN]``,
  ``tag -s``, ``tag -d`` and a bare ``tag`` are v3 tag refs;
* ``search`` uses the repository only when ``--repo`` is passed explicitly.

The ``repo-*`` verbs remain as aliases. Routing happens by rewriting the argv to
the ``repo-*`` form and re-parsing, so both spellings share one parser.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from opentine._cli_common import _find_run
from opentine.repo import Repo
from opentine.repository.ops import resolve_target


def _repo(args: argparse.Namespace) -> Repo | None:
    try:
        return Repo.open(getattr(args, "repo", None) or ".")
    except (OSError, ValueError, KeyError):
        return None


def _legacy_name(value: str) -> bool:
    if Path(value).exists():
        return True
    try:
        return _find_run(value) is not None
    except (OSError, ValueError):
        return False


def _resolves(repo: Repo, value: str) -> bool:
    try:
        return repo.has(resolve_target(repo, value))
    except (KeyError, ValueError, OSError):
        return False


def _v3(args: argparse.Namespace, values: list[str]) -> Repo | None:
    if getattr(args, "legacy", False):
        return None
    repo = _repo(args)
    if repo is None or any(_legacy_name(value) for value in values):
        return None
    return repo if all(_resolves(repo, value) for value in values) else None


def _tail(args: argparse.Namespace, repo: Repo) -> list[str]:
    tail = ["--repo", str(repo.worktree)]
    return tail + (["--json"] if getattr(args, "json", False) else [])


def v3_argv(args: argparse.Namespace) -> list[str] | None:
    """The ``repo-*`` argv this plain-verb invocation means, or None for legacy."""
    command = args.command
    if command == "show" and (repo := _v3(args, [args.run_id])):
        return ["repo-show", args.run_id, "--repo", str(repo.worktree)]
    if command == "diff" and (repo := _v3(args, [args.run_a, args.run_b])):
        flags = ["--exit-code"] if args.exit_code else []
        return ["repo-diff", args.run_a, args.run_b, *flags, *_tail(args, repo)]
    if command == "search" and getattr(args, "repo", None) and not args.legacy:
        repo = Repo.open(args.repo)
        return ["repo-search", " ".join(args.query), *_tail(args, repo)]
    if command == "fork" and getattr(args, "ref", None) and (repo := _v3(args, [args.run_id])):
        return _fork(args, repo)
    return None


def _fork(args: argparse.Namespace, repo: Repo) -> list[str]:
    step = str(args.from_step)
    if not step.startswith("event:"):
        payload = repo.get(resolve_target(repo, args.run_id)).payload()
        events = list(payload.get("events") or [])
        index = int(step)
        if not 1 <= index <= len(events):
            raise ValueError(f"--from-step {index} is out of range ({len(events)} steps)")
        step = events[index - 1]
    argv = ["repo-fork", args.run_id, "--from-event", step, "--ref", args.ref]
    if getattr(args, "model", None):
        argv += ["--model", args.model]
    return argv + _tail(args, repo)


def tag_is_v3(args: argparse.Namespace) -> bool:
    """Whether a ``tag`` invocation means a v3 tag ref (see the module doc)."""
    if args.legacy or args.add or args.remove:
        return False
    if args.sign or args.delete or args.target or args.force:
        return True
    if args.list:
        return args.run_id is None and _repo(args) is not None
    if args.run_id is None:
        return _repo(args) is not None
    # `tine tag NAME` alone: a legacy run id lists its labels, anything else is v3.
    return not _legacy_name(args.run_id) and _repo(args) is not None


def expand_alias(parser: argparse.ArgumentParser, argv: list[str]) -> list[str]:
    """``alias.NAME`` from a *trusted* porcelain file, for a non-builtin first word.

    A builtin can never be shadowed, and an alias expands once (no recursion).
    """
    import shlex

    from opentine import _porcelain_config as porcelain

    if not argv or argv[0].startswith("-"):
        return argv
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    if argv[0] in sub.choices:
        return argv
    repo = _repo(argparse.Namespace(repo="."))
    if repo is None:
        return argv
    try:
        expansion = porcelain.effective(repo.path).get(f"alias.{argv[0]}")
    except ValueError:
        return argv
    return [*shlex.split(expansion), *argv[1:]] if expansion else argv


def add_unify_args(sub: argparse._SubParsersAction) -> None:
    """``--legacy`` and ``--repo`` on the plain verbs, plus the v3 ``tag`` flags."""
    from opentine._repo_cli_keys import add_key_args

    for name in ("show", "diff", "search", "fork", "tag"):
        parser = sub.choices[name]
        parser.add_argument("--legacy", action="store_true", help="Act on legacy .tine files")
        parser.add_argument("--repo", help="A v3 repository (default: discover from .)")
    sub.choices["fork"].add_argument("--ref", help="v3: the ref to write the fork to")
    tag = sub.choices["tag"]
    tag.add_argument("target", nargs="?", help="v3: the run or ref to tag (default heads/main)")
    tag.add_argument("-s", "--sign", action="store_true", help="v3: sign the tag")
    tag.add_argument("-d", "--delete", metavar="NAME", help="v3: delete a tag")
    tag.add_argument("-f", "--force", action="store_true", help="v3: move an existing tag")
    tag.add_argument("-m", "--message", help="v3: a message in the signed claim")
    tag.add_argument("--signer", help="v3: the signer recorded on a signed tag")
    add_key_args(tag, signing=True)


__all__ = ["add_unify_args", "expand_alias", "tag_is_v3", "v3_argv"]
