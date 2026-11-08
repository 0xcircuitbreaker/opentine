"""``tine import|export --format git-ai``: Git AI Standard v3 notes (0.45.x).

* ``tine import REPO[::RANGE] --format git-ai [--sign-key KEY] [--force]``
  reads each ``refs/notes/ai`` note (every noted commit, or those in
  ``RANGE``) and writes it as an OpenTine attribution note under
  ``refs/notes/tine``, signed when ``--sign-key`` is given. A commit that
  already has an OpenTine attribution note keeps it unless ``--force``:
  OpenTine notes are canonical.
* ``tine export REV[..REV] --format git-ai [--output REPO] [--force]`` writes a
  v3 note under ``refs/notes/ai`` for each commit with an OpenTine
  attribution note; an existing Git AI note is kept unless ``--force``.

The format lives in :mod:`opentine._git_ai_notes`.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_json import emit
from opentine._git_link import GitLinkError, checked_revision, git, resolve_commit

FORMAT = "git-ai"


def _refuse(message: str) -> SystemExit:
    console.print(f"[red]{_terminal(message)}[/]")
    return SystemExit(1)


def _commits(cwd: Path, spec: str | None, default: list[str]) -> list[str]:
    if not spec:
        return default
    if ".." in spec:
        low, _, high = spec.partition("..")
        checked = [checked_revision(part) for part in (low, high) if part]
        return git(cwd, "rev-list", "--reverse", spec, "--").split() if checked else []
    return [resolve_commit(cwd, spec)]


def _report(args: argparse.Namespace, verb: str, cwd: Path, rows: list[dict[str, Any]]) -> None:
    if getattr(args, "json", False):
        emit({"command": verb, "format": FORMAT, "repo": str(cwd), "commits": rows})
        return
    done = [row for row in rows if not row.get("skipped")]
    console.print(
        f"[{BRAND}]# {verb.capitalize()}ed[/] {len(done)} Git AI note(s) "
        f"[{BRAND}]in[/] {_terminal(cwd)}"
    )
    for row in rows:
        if row.get("skipped"):
            console.print(f"  {row['commit'][:12]} skipped: {row['skipped']}", markup=False)


def import_git_ai(args: argparse.Namespace) -> bool:
    from opentine import _git_ai_convert as convert
    from opentine import _git_ai_notes as notes
    from opentine._line_attrib import read_note, sign, write_note

    used = [
        flag
        for flag, on in (
            ("--save", args.save),
            ("--repo", args.repo),
            ("--ref", args.ref is not None),
            ("--fleet", getattr(args, "fleet", False)),
            ("--all", getattr(args, "all", False)),
            ("--price", getattr(args, "price", False)),
            ("--from-default-location", args.from_default_location),
        )
        if on
    ]
    if used:
        raise _refuse(
            f"{', '.join(used)}: no effect with --format git-ai, which writes "
            "attribution notes into the git repository SOURCE."
        )
    if args.source is None:
        raise _refuse("--format git-ai needs SOURCE: a git repository, optionally REPO::RANGE.")
    root, _, spec = str(args.source).partition("::")
    cwd = Path(root)
    key = None
    rows: list[dict[str, Any]] = []
    try:
        if getattr(args, "sign_key", None):
            from opentine._signing_keys import ed25519_private_from_file

            key = ed25519_private_from_file(args.sign_key)
        noted = set(notes.noted_commits(cwd))
        for sha in _commits(cwd, spec or None, sorted(noted)):
            if sha not in noted:
                continue
            if read_note(cwd, sha) is not None and not args.force:
                rows.append({"commit": sha, "skipped": "has an OpenTine attribution note"})
                continue
            parsed = notes.read(cwd, sha)
            record = convert.to_attribution(cwd, sha, parsed or {"files": {}, "metadata": {}})
            if key is not None:
                record = sign(record, key)
            write_note(cwd, sha, record)
            rows.append(
                {
                    "commit": sha,
                    "lines_added": record["lines_added"],
                    "lines_attributed": record["lines_attributed"],
                    "signed": "signature" in record,
                }
            )
    except (GitLinkError, OSError, ValueError) as exc:
        raise _refuse(f"Import failed: {exc}") from exc
    _report(args, "import", cwd, rows)
    return True


def export_git_ai(args: argparse.Namespace) -> None:
    from opentine import _git_ai_convert as convert
    from opentine import _git_ai_notes as notes
    from opentine._cli_flags import refuse_unhonoured
    from opentine._line_attrib import read_note

    refuse_unhonoured(
        args,
        ("compress", "endpoint", "allow_insecure"),
        mode="with --format git-ai",
        hint="Notes go to the --output repository.",
    )
    cwd = Path(args.output) if args.output else Path.cwd()
    rows: list[dict[str, Any]] = []
    try:
        existing = set(notes.noted_commits(cwd))
        for sha in _commits(cwd, args.run_id, []):
            record = read_note(cwd, sha)
            if record is None:
                rows.append({"commit": sha, "skipped": "no OpenTine attribution note"})
                continue
            if sha in existing and not args.force:
                rows.append({"commit": sha, "skipped": "already has a Git AI note"})
                continue
            notes.write(cwd, sha, convert.from_attribution(sha, record))
            rows.append({"commit": sha, "lines_attributed": record.get("lines_attributed", 0)})
    except (GitLinkError, OSError, ValueError) as exc:
        raise _refuse(f"Export failed: {exc}") from exc
    _report(args, "export", cwd, rows)


def add_sign_key(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--sign-key", metavar="KEY", help="git-ai: sign imported attribution with this Ed25519 key"
    )


__all__ = ["FORMAT", "add_sign_key", "export_git_ai", "import_git_ai"]
