"""``tine enable [--agent NAME] [--dry-run] --repo PATH`` and ``tine disable``.

``enable`` points each agent CLI's hook file at the per-turn protocol
(:mod:`opentine._enable_shims`) and sets ``hooks.capture`` in the repository's
porcelain config, which only counts once that file is trusted (it stays trusted
when ``tine enable`` is the writer of an already-trusted or brand-new file).
``--dry-run`` prints the exact edit as a unified diff and writes nothing.

Before the first edit of a file its original bytes (or its absence) are saved to
``$XDG_CONFIG_HOME/opentine/enabled/<agent>.json`` with the digest of what
``enable`` wrote. ``disable`` puts those bytes back **byte for byte** when the
file is still exactly what ``enable`` wrote; if it was edited since, only the
shim entries are removed (the user's later edits are kept) and that is said.
"""

from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._canon import atomic_write_text
from opentine._cli_common import _terminal, console
from opentine._cli_hook_agents import AGENTS, read_config
from opentine._codec_io import atomic_write_bytes
from opentine._enable_shims import render, with_shims, without_shims


def add_enable_parsers(subparsers: argparse._SubParsersAction) -> None:
    verbs = (
        ("enable", "Capture every agent turn through `tine hook capture`"),
        ("disable", "Remove the per-turn hooks, restoring each agent config"),
    )
    for verb, summary in verbs:
        parser = subparsers.add_parser(verb, help=summary)
        parser.add_argument(
            "--agent", action="append", choices=sorted(AGENTS),
            help="Only this agent CLI (repeatable; default: every one)",
        )  # fmt: skip
        parser.add_argument("--dry-run", action="store_true", help="Show the edit, write nothing")
        if verb == "enable":
            parser.add_argument("--repo", help="v3 repository the turns are recorded into")


def _state(name: str) -> Path:
    home = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(home, "opentine", "enabled", f"{name}.json")


def _bytes(path: Path) -> bytes | None:
    if path.is_symlink():
        raise ValueError(f"{path} is a symlink; edit its target by hand or pass a real file")
    return path.read_bytes() if path.exists() else None


def _diff(path: Path, old: bytes | None, new: bytes | None) -> str:
    lines = [(data or b"").decode("utf-8", "replace").splitlines(keepends=True)
             for data in (old, new)]  # fmt: skip
    name = str(path)
    text = "".join(difflib.unified_diff(*lines, fromfile=name, tofile=name))
    return text or f"(no change to {name})\n"


def _write(path: Path, data: bytes | None, mode: int | None) -> None:
    if data is None:
        path.unlink(missing_ok=True)
        return
    atomic_write_bytes(path, data, fsync=True)
    if mode is not None:
        os.chmod(path, mode)


def _enable_one(name: str, repo: Path, dry_run: bool) -> None:
    agent = AGENTS[name]
    path = agent.config()
    original = _bytes(path)
    document = read_config(path)  # refuses non-JSON / non-object files before anything
    new = render(with_shims(document, agent, repo))
    if dry_run:
        console.print(_diff(path, original, new), markup=False, end="")
        return
    state = _state(name)
    record = json.loads(state.read_text(encoding="utf-8")) if state.exists() else None
    current = hashlib.sha256(original).hexdigest() if original is not None else None
    if record is None or record.get("written_sha256") != current:
        # First enable, or the file changed since ours: what is there now (minus any
        # shims) is the original to restore, so later edits are never rolled back.
        base = original if record is None else render(without_shims(document))
        record = {
            "path": str(path),
            "existed": original is not None,
            "original": base64.b64encode(base or b"").decode("ascii"),
            "mode": path.stat().st_mode & 0o777 if original is not None else None,
        }
    mode = path.stat().st_mode & 0o777 if original is not None else 0o600
    _write(path, new, mode)
    record["written_sha256"] = hashlib.sha256(new).hexdigest()
    state.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(state, json.dumps(record, indent=2, sort_keys=True) + "\n")
    console.print(f"  {name:<12} enabled        {_terminal(path)}")


def _disable_one(name: str, dry_run: bool) -> None:
    state = _state(name)
    record: dict[str, Any] | None = None
    if state.exists():
        record = json.loads(state.read_text(encoding="utf-8"))
    path = Path(record["path"]) if record else AGENTS[name].config()
    current = _bytes(path)
    note = "restored"
    if (
        record
        and current is not None
        and (hashlib.sha256(current).hexdigest() == record.get("written_sha256"))
    ):
        target = base64.b64decode(record["original"]) if record["existed"] else None
    elif current is None:
        target, note = None, "absent"
    else:
        target, note = render(without_shims(read_config(path))), "shims removed (edited since)"
        if json.loads(target) == json.loads(current):
            target, note = current, "unchanged"
    if dry_run:
        console.print(_diff(path, current, target), markup=False, end="")
        return
    if target != current:
        _write(path, target, record.get("mode") if record else None)
    state.unlink(missing_ok=True)
    console.print(f"  {name:<12} {note:<14} {_terminal(path)}", markup=False)


def _set_capture(repo: Path) -> None:
    from opentine import _porcelain_config as porcelain

    settings = porcelain.load(repo)
    if settings["config"].get("hooks.capture") != "true":
        settings["config"]["hooks.capture"] = "true"
        porcelain.save(repo, settings)
    if not porcelain.trusted(repo):
        console.print("hooks.capture is set but this repository's config is not trusted: "
                      "review it, then run `tine config --trust`.", markup=False)  # fmt: skip


def _run(args: argparse.Namespace, enable: bool) -> None:
    repo = None
    if enable:
        from opentine._cli_hook import _repo

        repo = _repo(args.repo)
    failed = False
    for name in args.agent or sorted(AGENTS):
        try:
            if enable:
                assert repo is not None
                _enable_one(name, repo, args.dry_run)
            else:
                _disable_one(name, args.dry_run)
        except (OSError, ValueError) as exc:
            failed = True
            console.print(f"  [red]{name:<12} refused[/]        {_terminal(exc)}")
    if enable and not args.dry_run and not failed:
        assert repo is not None
        _set_capture(repo)
    if failed:
        raise SystemExit(1)


def cmd_enable(args: argparse.Namespace) -> None:
    _run(args, True)


def cmd_disable(args: argparse.Namespace) -> None:
    _run(args, False)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {
    "enable": cmd_enable,
    "disable": cmd_disable,
}

__all__ = ["COMMANDS", "add_enable_parsers", "cmd_disable", "cmd_enable"]
