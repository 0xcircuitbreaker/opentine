"""Hooks ``tine git install-hook`` adds beside ``commit-msg`` (0.45).

* ``--push`` / ``--strict``: the pre-push hook (:mod:`opentine._git_push_sync`).
* ``--ai-share`` (opt-in): a ``post-commit`` hook that prints one line, the
  share of the commit's added lines that its linked runs wrote::

      tine: 12/40 added line(s) by agents (30%) on 1a2b3c4d5e6f

  It reads the commit's attribution note when there is one, else matches the
  linked runs' recorded writes in memory. It writes nothing and never fails a
  commit.

Every non-global install also sets ``notes.rewriteRef=refs/notes/tine`` so
``commit --amend`` and ``rebase`` copy run and attribution notes to the
rewritten commit.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from opentine._git_link import GitLinkError, commit_runs, resolve_commit, top_level
from opentine._git_link_hook import CHAINED, configured_source, install_hook

HOOK = "post-commit"
MARKER = "# opentine:post-commit"


def add_install_flags(install: Any) -> None:
    install.add_argument("--push", action="store_true", help="Also push trailer runs on git push")
    install.add_argument("--strict", action="store_true", help="With --push: block on failure")
    install.add_argument(
        "--ai-share", action="store_true", help="Print the AI share of each commit (post-commit)"
    )


def script() -> str:
    python = Path(sys.executable).as_posix().replace('"', '\\"')
    return (
        "#!/bin/sh\n"
        f"{MARKER} (managed by `tine git install-hook --ai-share`; safe to delete)\n"
        f'if [ -x "$0{CHAINED}" ]; then "$0{CHAINED}" "$@" || exit $?; fi\n'
        f'"{python}" -I -m opentine.cli git share-line 2>/dev/null || true\n'
        "exit 0\n"
    )


def extra_hooks(args: argparse.Namespace, cwd: Path) -> tuple[list[Path], bool]:
    """Install the opt-in hooks *args* asks for; return them and whether rewriteRef is set."""
    from opentine._git_push_sync import HOOK as PRE_PUSH
    from opentine._git_push_sync import script as push_script
    from opentine._line_attrib import configure_rewrite_ref, rewrite_ref_configured

    hooks: list[Path] = []
    if args.push or args.strict:  # also carry the trailers' runs on every git push
        text = push_script(strict=args.strict)
        hooks.append(install_hook(cwd, global_=args.global_, hook=PRE_PUSH, text=text))
    if getattr(args, "ai_share", False):
        hooks.append(install_hook(cwd, global_=args.global_, hook=HOOK, text=script()))
    if args.global_:
        return hooks, False
    configure_rewrite_ref(cwd)
    return hooks, rewrite_ref_configured(cwd)


def _record(cwd: Path, sha: str) -> dict[str, Any] | None:
    from opentine._git_link_runs import open_catalog
    from opentine._line_attrib import added_lines, attribute, read_note, writers

    record = read_note(cwd, sha)
    if record is not None:
        return record
    names = [run for run, _source in commit_runs(cwd, sha)]
    repo, runs_dir = configured_source(cwd)
    if not names or not repo and not (runs_dir and Path(runs_dir).is_dir()):
        return None
    catalog = open_catalog(repo or None, Path(runs_dir))
    loaded = []
    for name in names:
        try:
            loaded.append((catalog.canonical(name), catalog.load(name)))
        except Exception:  # noqa: BLE001 - a run not held here attributes nothing
            continue
    return attribute(top_level(cwd), added_lines(cwd, sha), writers(loaded))


def share_line(cwd: Path, revision: str = "HEAD") -> str:
    """The one-line AI share of *revision*, or ``""`` when it links no run."""
    sha = resolve_commit(cwd, revision)
    record = _record(cwd, sha)
    added = int((record or {}).get("lines_added") or 0)
    if not added:
        return ""
    ai = int(record.get("lines_attributed") or 0)  # type: ignore[union-attr]
    return f"tine: {ai}/{added} added line(s) by agents ({ai / added:.0%}) on {sha[:12]}"


def cmd_share_line(args: argparse.Namespace) -> None:
    try:
        line = share_line(Path.cwd(), getattr(args, "commit", None) or "HEAD")
    except (GitLinkError, OSError, ValueError):
        return
    if line:
        print(line)


__all__ = ["add_install_flags", "cmd_share_line", "extra_hooks", "script", "share_line"]
