"""``tine prompt push|label|get|list|verify|link`` (0.47, SPEC 4.21).

The prompt registry. ``push`` signs the next version of a named template
(Ed25519, ``--key``) and moves ``prompts/<name>/head``; ``--label`` also points
a label at it. ``label`` moves a label to a version (``NAME`` is the head,
``NAME@vN`` a version). ``get`` resolves ``NAME``, ``NAME@LABEL`` or
``NAME@vN`` and, with ``--var KEY=VALUE``, renders it. ``verify`` checks a
prompt's whole history (``--pubkey`` pins its key; exit 4 on a failure).
``link`` records the version a run used in that run's annotation
(``metadata.prompt``: name, version and digest), so ``tine log`` and ``tine
eval`` can say which prompt bytes produced a run.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._cli_errors import VERIFICATION_FAILED, fail
from opentine._cli_json import emit
from opentine._cli_remote_target import add_remote_args

ACTIONS = ("push", "label", "get", "list", "verify", "link", "sync")


def add_prompt_parser(sub: Any) -> None:
    prompt = sub.add_parser("prompt", help="Signed, versioned prompts (opentine.prompt)")
    actions = prompt.add_subparsers(dest="prompt_action", required=True)
    push = actions.add_parser("push", help="Sign and store the next version of a prompt")
    push.add_argument("name", help="[a-z0-9][a-z0-9._-]{0,63}")
    source = push.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", metavar="PATH", help="Read the template from a file")
    source.add_argument("--template", help="The template text ({{name}} placeholders)")
    push.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
    push.add_argument("--model", help="The model the template was written for")
    push.add_argument("--label", action="append", default=[], help="Also point LABEL here")
    push.add_argument("--created-at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    label = actions.add_parser("label", help="Point a label at a version (moves the label)")
    label.add_argument("spec", metavar="NAME[@vN]")
    label.add_argument("label")
    get = actions.add_parser("get", help="Resolve NAME, NAME@LABEL or NAME@vN")
    get.add_argument("spec", metavar="NAME[@LABEL|@vN]")
    get.add_argument("--var", action="append", default=[], metavar="KEY=VALUE",
                     help="Render the template with this value (repeatable)")  # fmt: skip
    actions.add_parser("list", help="Every prompt, its head version and labels")
    verify = actions.add_parser("verify", help="Check a prompt's whole signed history")
    verify.add_argument("name")
    verify.add_argument("--pubkey", metavar="PUB", help="Pin the prompt's Ed25519 key")
    link = actions.add_parser("link", help="Record the prompt version a run used")
    link.add_argument("spec", metavar="NAME[@LABEL|@vN]")
    link.add_argument("run", metavar="RUN_ID")
    sync = actions.add_parser("sync", help="Send and fetch prompt histories and labels")
    add_remote_args(sync)
    for parser in actions.choices.values():
        parser.add_argument("--repo", default=".")
        parser.add_argument("--json", action="store_true")


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    from opentine import _prompt

    return {"name": record["name"], "version": record["version"],
            "digest": _prompt.digest(record), "variables": list(record["variables"]),
            "model": record["model"]}  # fmt: skip


def _version_of(spec: str) -> tuple[str, int | None]:
    name, _, which = spec.partition("@")
    if not which:
        return name, None
    if which[:1] == "v" and which[1:].isdigit():
        return name, int(which[1:])
    raise ValueError("label takes NAME or NAME@vN")


def _push(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], str]:
    from opentine import _prompt
    from opentine._signing_keys import ed25519_private_from_file
    from opentine.repository import _registry_refs as refs

    text = Path(args.file).read_text("utf-8") if args.file else args.template
    key = ed25519_private_from_file(args.key)
    previous = refs.prompt_head(repo, args.name)
    record = _prompt.build(args.name, text, previous=previous, model=args.model,
                           created_at=args.created_at)  # fmt: skip
    signed = _prompt.sign(record, key)
    refs.push_prompt(repo, signed)
    for label in args.label:
        refs.set_label(repo, args.name, label)
    body = {"prompt": _summary(signed), "labels": refs.labels(repo, args.name), "record": signed}
    return body, f"prompt {args.name} v{signed['version']}: {_prompt.digest(signed)}"


def _get(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], str]:
    from opentine import _prompt
    from opentine.repository import _registry_refs as refs

    record = refs.resolve(repo, args.spec)
    _prompt.check(record)
    labels = refs.labels(repo, record["name"])
    body: dict[str, Any] = {"prompt": _summary(record), "labels": labels, "record": record}
    if args.var:
        values = dict(item.partition("=")[::2] for item in args.var)
        body["rendered"] = _prompt.render(record, values)
    return body, body.get("rendered", record["template"])


def _link(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], str]:
    from opentine import _prompt
    from opentine.repository import _registry_refs as refs
    from opentine.repository._annotations import load_run_annotation, write_run_annotation
    from opentine.repository.ops import resolve_target

    record = refs.resolve(repo, args.spec)
    _prompt.check(record)
    run = resolve_target(repo, args.run)
    if not run.startswith("run:"):
        raise ValueError(f"{args.run} does not name a run")
    metadata, tags = load_run_annotation(repo, run)
    link = {key: _summary(record)[key] for key in ("name", "version", "digest")}
    write_run_annotation(repo, run, {**metadata, "prompt": link}, tags)
    return {
        "run": run,
        "prompt": _summary(record),
    }, f"{run} used {record['name']} v{link['version']}"


def _act(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    from opentine import _prompt
    from opentine._signed_record import RecordError
    from opentine.repository import Repo
    from opentine.repository import _registry_refs as refs

    repo = Repo.open(args.repo)
    action = args.prompt_action
    if action == "push":
        return _push(args, repo)
    if action == "get":
        return _get(args, repo)
    if action == "link":
        return _link(args, repo)
    if action == "sync":
        from opentine._cli_memory import remote_sync

        body = remote_sync(args, "prompts/")
        return body, f"sent {len(body['sent'])}, received {len(body['received'])}, " + (
            f"{len(body['conflicts'])} diverged"
        )
    if action == "label":
        name, version = _version_of(args.spec)
        record = refs.set_label(repo, name, args.label, version)
        return ({"prompt": _summary(record), "labels": refs.labels(repo, name)},
                f"{name}@{args.label} -> v{record['version']}")  # fmt: skip
    if action == "list":
        rows = []
        for name in refs.prompt_names(repo):
            head = refs.prompt_head(repo, name)
            rows.append({**_summary(head), "labels": refs.labels(repo, name)})  # type: ignore[arg-type]
        text = "\n".join(f"{r['name']}\tv{r['version']}\t{r['digest']}" for r in rows)
        return {"prompts": rows}, text or "no prompts"
    history = refs.prompt_history(repo, args.name)
    if not history:
        raise KeyError(f"no prompt {args.name}")
    pinned = None
    if args.pubkey:
        from opentine._signing_keys import ed25519_public_from_file

        pinned = ed25519_public_from_file(args.pubkey).public_bytes_raw()
    last = _prompt.check(history[0], public_key=pinned)
    if history[0]["version"] != 1:  # a history cut short is not a verified chain
        raise RecordError("prompt.chain-break", f"the history of {args.name} misses version 1")
    for previous, record in zip(history, history[1:]):
        last = _prompt.check(record, previous=previous)
    result = {**last, "versions": len(history), "state": "verified" if pinned else "verified-tofu"}
    return {"result": result}, f"verified {len(history)} version(s) of {args.name}"


def cmd_prompt(args: argparse.Namespace) -> None:
    from opentine._signed_record import RecordError

    try:
        body, text = _act(args)
    except RecordError as exc:
        fail(f"{exc.code}: {exc}", VERIFICATION_FAILED, prefix="tine prompt: ")
    except (KeyError, LookupError, OSError, ValueError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(str(message), prefix="tine prompt: ")
    if args.json:
        emit({"command": "prompt", "action": args.prompt_action, "ok": True, **body})
    else:
        print(text)


__all__ = ["ACTIONS", "add_prompt_parser", "cmd_prompt"]
