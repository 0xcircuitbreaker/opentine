"""``tine git attribute`` / ``tine git attribution`` and ``tine stats --ai-share``.

``attribute COMMIT [RUNS...] [--sign-key KEY]`` writes the line attribution
note (:mod:`opentine._line_attrib`) and, unless ``--no-configure``, adds
``notes.rewriteRef=refs/notes/tine`` to the repository's git config so the
note follows the commit through ``rebase`` and ``commit --amend``.
``attribution COMMIT [--verify] [--pubkey KEY] [--format agent-trace]`` reads
it back.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._cli_common import _runs_dir, console
from opentine._cli_errors import fail
from opentine._cli_json import emit
from opentine._cli_who_render import emit_or_print
from opentine._git_link import (
    RUN_ID,
    GitLinkError,
    NoteEntry,
    commit_runs,
    resolve_commit,
    top_level,
)
from opentine._git_link import write_note as write_run_note
from opentine._git_push_sync import add_push_runs_parser, cmd_push_runs
from opentine._git_share_hook import cmd_share_line
from opentine._line_attrib import (
    added_lines,
    attribute,
    configure_rewrite_ref,
    read_note,
    rewrite_ref_configured,
    sign,
    verify,
    write_note,
    writers,
)


def _attribute(args: argparse.Namespace) -> None:
    from opentine._git_link_runs import open_catalog

    cwd = Path.cwd()
    sha = resolve_commit(cwd, args.commit)
    names = list(args.runs) or [run for run, _source in commit_runs(cwd, sha)]
    bad = [name for name in names if not RUN_ID.fullmatch(name)]
    if bad or not names:
        fail(f"not a run id: {bad[0][:80]!r}" if bad else "no runs given or linked", 2)
    catalog = open_catalog(getattr(args, "repo", None), _runs_dir())
    loaded = []
    for name in names:
        try:
            loaded.append((catalog.canonical(name), catalog.load(name)))
        except Exception:  # noqa: BLE001 - a run not held here attributes nothing
            continue
    record = attribute(top_level(cwd), added_lines(cwd, sha), writers(loaded))
    if args.sign_key:
        from opentine._signing_keys import ed25519_private_from_file

        record = sign(record, ed25519_private_from_file(args.sign_key))
    write_run_note(cwd, sha, [NoteEntry(name) for name, _run in loaded])
    write_note(cwd, sha, record)
    configured = False if args.no_configure else configure_rewrite_ref(cwd)
    payload = {
        "commit": sha,
        "runs": [name for name, _run in loaded],
        "lines_added": record["lines_added"],
        "lines_attributed": record["lines_attributed"],
        "signed": "signature" in record,
        "rewrite_ref_configured": rewrite_ref_configured(cwd),
        "rewrite_ref_added": configured,
    }
    emit_or_print(args, "git attribute", payload, lambda: console.print(
        f"Attributed {record['lines_attributed']}/{record['lines_added']} added line(s) on "
        f"{sha[:12]} under refs/notes/tine" + (" (signed)" if payload["signed"] else "")
    ))  # fmt: skip


def _attribution(args: argparse.Namespace) -> None:
    cwd = Path.cwd()
    sha = resolve_commit(cwd, args.commit)
    record = read_note(cwd, sha)
    if record is None:
        fail(f"{sha[:12]} has no line attribution note", 1)
    if args.format == "agent-trace":
        from opentine._line_attrib_share import agent_trace

        emit(agent_trace(cwd, sha, record))
        return
    payload: dict[str, Any] = {"commit": sha, "attribution": record}
    if args.verify or args.pubkey:
        public = None
        if args.pubkey:
            from opentine._signing_keys import ed25519_public_from_file

            public = ed25519_public_from_file(args.pubkey)
        payload["verification"] = verify(cwd, sha, record, public)
    ok = payload.get("verification", {}).get("content_matches", True) and payload.get(
        "verification", {}
    ).get("signature", {}).get("valid", True)

    def human() -> None:
        for entry in record.get("files") or []:
            for item in entry["ranges"]:
                console.print(
                    f"{entry['path']}:{item['start_line']}-{item['end_line']}  "
                    f"{item.get('run')}  step {item.get('seq')}  {item.get('model') or '-'}",
                    markup=False,
                    highlight=False,
                )
        if "verification" in payload:
            console.print("verified" if ok else f"NOT verified: {payload['verification']}")

    emit_or_print(args, "git attribution", payload, human)
    if not ok:
        raise SystemExit(1)


def _guarded(handler):
    def run(args: argparse.Namespace) -> None:
        try:
            handler(args)
        except (GitLinkError, ValueError, OSError) as exc:
            fail(str(exc), 2)

    return run


HANDLERS = {
    "push-runs": cmd_push_runs,
    "attribute": _guarded(_attribute),
    "attribution": _guarded(_attribution),
    "share-line": cmd_share_line,
}


def add_git_extras(git_sub: Any) -> None:
    add_push_runs_parser(git_sub)
    write = git_sub.add_parser("attribute", help="Sign which run and step wrote each added line")
    write.add_argument("commit")
    write.add_argument("runs", nargs="*", help="Run ids (default: the runs the commit links)")
    write.add_argument("--sign-key", metavar="KEY", help="Ed25519 private key to sign with")
    write.add_argument(
        "--no-configure", action="store_true", help="Do not set notes.rewriteRef in git config"
    )
    write.add_argument("--repo", metavar="PATH", help="Read a v3 repository instead")
    write.add_argument("--json", action="store_true")
    read = git_sub.add_parser("attribution", help="Show, verify or export a commit's attribution")
    read.add_argument("commit")
    read.add_argument("--verify", action="store_true", help="Check signature and line hashes")
    read.add_argument("--pubkey", metavar="KEY", help="Verify against this Ed25519 public key")
    read.add_argument("--format", choices=("opentine", "agent-trace"), default="opentine")
    read.add_argument("--json", action="store_true")
    share = git_sub.add_parser("share-line", help=argparse.SUPPRESS)  # the post-commit hook
    share.add_argument("commit", nargs="?", default="HEAD")


def cmd_ai_share(args: argparse.Namespace) -> None:
    from opentine._line_attrib_share import ai_share

    try:
        report = ai_share(Path.cwd(), args.rev or "HEAD")
    except GitLinkError as exc:
        fail(str(exc), 2)
    payload = {"mode": "ai-share", **report}
    emit_or_print(args, "stats", payload, lambda: console.print(
        f"{report['ai_lines']}/{report['total_lines']} line(s) at {report['revision'][:12]} "
        f"attributed to agents ({report['ai_share']:.1%})"
    ))  # fmt: skip


__all__ = ["HANDLERS", "add_git_extras", "cmd_ai_share"]
