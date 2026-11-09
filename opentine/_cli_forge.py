"""``tine forge publish``: show a commit's evidence on its forge (0.48, SPEC 4.24).

Builds one ``opentine.forge-check`` record for a commit (AI share, verify
status, the blame overlay and a link to an offline-verifiable bundle) and
posts it: a GitHub check run (and PR comment), a GitLab commit status (and MR
note), a Forgejo/Gitea commit status (and PR comment), or, for Entire,
checkpoint refs and a git note in the code checkout (:mod:`opentine._forge_entire`).

The project is resolved by ``--forge-repo-id`` against the verified project
chain of ``--repo``. Tokens come only from environment variables (or a GitHub
App key file) and are never printed. ``--dry-run`` builds the record and the
request plan without a token or any network. Token scopes: ``docs/FORGES.md``.
The command exits 0 whatever the conclusion: the gate decides the job, not this.
"""

from __future__ import annotations

import argparse
import os
from typing import Any

from opentine._cli_errors import VERIFICATION_FAILED, fail
from opentine._cli_json import emit

FORGES = ("github", "gitlab", "forgejo", "entire")
_REPO_ID_ENV = {"github": "GITHUB_REPOSITORY_ID", "gitlab": "CI_PROJECT_ID"}
_API_ENV = {"github": "GITHUB_API_URL", "gitlab": "CI_API_V4_URL"}


def add_forge_parser(sub: Any) -> None:
    forge = sub.add_parser("forge", help="Show AI share and verify status on a forge (PR checks)")
    actions = forge.add_subparsers(dest="forge_action", required=True)
    p = actions.add_parser("publish", help="Post a commit's opentine.forge-check to its forge")
    p.add_argument("--forge", required=True, choices=FORGES)
    p.add_argument("--forge-repo-id", help="The forge's repository id (resolves the project)")
    p.add_argument("--repo-slug", help="OWNER/NAME on GitHub or Forgejo (GITHUB_REPOSITORY)")
    p.add_argument("--api-url", help="API base URL (GITHUB_API_URL, CI_API_V4_URL)")
    p.add_argument("--rev", default="HEAD", help="The commit to report on")
    p.add_argument("--code", default=".", metavar="DIR", help="The code checkout")
    p.add_argument("--repo", default=".", help="The run repository holding the project")
    p.add_argument(
        "--require-project",
        action="store_true",
        help="Refuse when the run repository has no project",
    )
    p.add_argument(
        "--verify",
        action="append",
        default=[],
        metavar="FILE",
        dest="verify_outputs",
        help="A `tine verify --json` output (repeatable)",
    )
    p.add_argument("--bundle", metavar="FILE", help="The bundle the check links to")
    p.add_argument("--bundle-url", metavar="URL", help="Where the bundle is downloadable")
    p.add_argument("--pr", type=int, help="GitHub/Forgejo PR number: also post one comment")
    p.add_argument("--mr", type=int, help="GitLab MR iid: also post one note")
    p.add_argument("--token-env", metavar="NAME", help="Environment variable with the token")
    p.add_argument("--app-id", help="GitHub App id (with --app-key-file, --installation-id)")
    p.add_argument("--app-key-file", metavar="PATH", help="GitHub App private key (PEM)")
    p.add_argument("--installation-id", help="GitHub App installation id")
    p.add_argument("--comment-author", help="The login whose marked comment is edited")
    p.add_argument(
        "--run",
        action="append",
        default=[],
        metavar="RUN",
        help="Entire: a run to map (default: the runs the commit's notes name)",
    )
    p.add_argument("--out", metavar="FILE", help="Also write the record here")
    p.add_argument("--dry-run", action="store_true", help="Build the record and plan only")
    p.add_argument("--json", action="store_true")


def _defaults(args: argparse.Namespace) -> None:
    env = os.environ
    if not args.forge_repo_id and args.forge in _REPO_ID_ENV:
        args.forge_repo_id = env.get(_REPO_ID_ENV[args.forge]) or None
    if not args.repo_slug and args.forge == "github":
        args.repo_slug = env.get("GITHUB_REPOSITORY") or None
    if not args.api_url and args.forge in _API_ENV:
        args.api_url = env.get(_API_ENV[args.forge]) or None
    if not args.forge_repo_id:
        raise ValueError("--forge-repo-id is required (the forge's own repository id)")
    if args.bundle_url and not args.bundle:
        raise ValueError("--bundle-url needs --bundle FILE: a link must be checkable offline")


def record(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _forge_check
    from opentine import _forge_inputs as inputs

    _defaults(args)
    project = inputs.resolve_project(
        args.repo, args.forge, args.forge_repo_id, required=args.require_project
    )
    commit = inputs.commit_of(args.code, args.rev)
    state, runs = inputs.verify_state(args.verify_outputs)
    ai_lines, total = inputs.share(args.code, commit)
    digest = inputs.bundle_digest(args.bundle) if args.bundle else None
    return _forge_check.build(
        forge=args.forge,
        forge_repo_id=args.forge_repo_id,
        project_id=project,
        commit=commit,
        verify_state=state,
        runs=runs,
        ai_lines=ai_lines,
        total_lines=total,
        bundle_url=args.bundle_url,
        bundle_digest=digest,
        overlay=inputs.overlay(args.code, commit),
    )


def _post(args: argparse.Namespace, check: dict[str, Any]) -> dict[str, Any]:
    from opentine import _forge_entire, _forge_github, _forge_inputs, _forge_post, _forge_status

    if args.forge == "entire":
        runs = args.run or _forge_inputs.runs_of(check["overlay"])
        if args.dry_run:
            return {"plan": _forge_entire.plan(args, check, runs), "posted": []}
        rows = _forge_entire.publish(args.code, check, runs)
        return {"posted": rows, "push": _forge_entire.push_command(rows)}
    module = _forge_github if args.forge == "github" else _forge_status
    if args.dry_run:
        return {"plan": module.plan(args, check), "posted": []}
    with _forge_post.client() as session:
        if args.forge == "github":
            rows = _forge_github.publish(args, check, session)
        else:
            rows = getattr(_forge_status, args.forge)(args, check, session)
    return {"posted": rows}


def cmd_forge(args: argparse.Namespace) -> None:
    import httpx

    from opentine._bundle import BundleError
    from opentine._codec_io import atomic_write_bytes
    from opentine._forge_check import encode
    from opentine._forge_post import ForgeError
    from opentine._git_link import GitLinkError
    from opentine._signed_record import RecordError

    try:
        check = record(args)
        if args.out:
            from pathlib import Path

            atomic_write_bytes(Path(args.out), encode(check))
        result = _post(args, check)
    except (RecordError, BundleError) as exc:
        code = getattr(exc, "code", "bundle.invalid")
        fail(f"{code}: {exc}", VERIFICATION_FAILED, prefix="tine forge: ")
    except httpx.HTTPError as exc:
        fail(f"the forge could not be reached ({type(exc).__name__})", prefix="tine forge: ")
    except (ForgeError, GitLinkError, KeyError, OSError, ValueError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(str(message), prefix="tine forge: ")
    body = {
        "command": "forge",
        "action": "publish",
        "ok": True,
        "forge": args.forge,
        "dry_run": bool(args.dry_run),
        "check": check,
        **result,
    }
    if args.json:
        emit(body)
        return
    from opentine._forge_post import title

    print(f"{title(check)} ({check['conclusion']}) for {check['commit'][:12]}")
    for row in body.get("plan", []):
        print(f"would {row['method']} {row['target']}: {row['path']}")
    for row in body["posted"]:
        print(f"{row['target']} {row['state']}")
    if body.get("push"):
        print(f"publish with: {body['push']}")


__all__ = ["add_forge_parser", "cmd_forge", "record"]
