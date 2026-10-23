"""``tine log``: run history across refs and forks, like ``git log --graph --all``.

``repo-log`` walks the *events* of one run. ``tine log`` walks *runs*: each ref
names a run, each run may name the run it was ``forked_from``, and together they
form a tree. The graph view draws that tree with each run's ref names, model,
status, step count and cost; ``--oneline`` is one run per line. With an event
argument-free ``REF`` and no ``--graph`` it falls back to the event log, so
``tine log heads/main`` keeps meaning what ``tine repo-log heads/main`` means.
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal
from opentine._cli_json import emit
from opentine._repo_cli_plumbing import cmd_repo_log
from opentine._repo_cli_render import _short_oid
from opentine.repo import Repo

MAX_RUNS = 5_000
RUN_SPACES = ("heads/", "experiments/", "promotions/", "tags/", "remotes/")


def _cost(repo: Repo, events: list[str]) -> float:
    total = 0.0
    for event in events[:10_000]:
        try:
            value = float(repo.get(event).payload().get("cost") or 0)
        except (KeyError, TypeError, ValueError, OverflowError):
            continue
        if math.isfinite(value):
            total += value
    return total


def collect(repo: Repo, starts: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Runs reachable from *starts* through ``forked_from``, with display fields."""
    nodes: dict[str, dict[str, Any]] = {}
    labels: dict[str, list[str]] = {}
    for name, oid in starts.items():
        labels.setdefault(oid, []).append(name)
    queue = list(dict.fromkeys(starts.values()))
    while queue and len(nodes) < MAX_RUNS:
        oid = queue.pop()
        if oid in nodes or not oid.startswith("run:") or not repo.has(oid):
            continue
        payload = repo.get(oid).payload()
        events = list(payload.get("events") or [])
        parent = payload.get("forked_from") if isinstance(payload.get("forked_from"), str) else None
        nodes[oid] = {
            "run_id": oid,
            "parent": parent,
            "refs": sorted(labels.get(oid, [])),
            "model": str(payload.get("model") or ""),
            "status": str(payload.get("status") or ""),
            "steps": len(events),
            "cost": _cost(repo, events),
            "created_at": payload.get("created_at") or 0,
        }
        if parent:
            queue.append(parent)
    return nodes


def _line(node: dict[str, Any]) -> str:
    refs = f" ({', '.join(node['refs'])})" if node["refs"] else ""
    model = f" {node['model']}" if node["model"] else ""
    return (
        f"{_short_oid(node['run_id'])}{_terminal(refs)}{_terminal(model)} "
        f"{_terminal(node['status'])} {node['steps']} steps ${node['cost']:.4f}"
    )


def _children(nodes: dict[str, dict[str, Any]]) -> dict[str | None, list[str]]:
    children: dict[str | None, list[str]] = {}
    for oid, node in nodes.items():
        parent = node["parent"] if node["parent"] in nodes else None
        children.setdefault(parent, []).append(oid)
    for kids in children.values():
        kids.sort(key=lambda oid: (nodes[oid]["created_at"], oid))
    return children


def graph_lines(nodes: dict[str, dict[str, Any]]) -> list[str]:
    """A fork tree drawn with ``*`` nodes and ``|``/``\\`` guides, roots first."""
    children = _children(nodes)
    lines: list[str] = []
    stack: list[tuple[str, int]] = [(oid, 0) for oid in reversed(children.get(None, []))]
    while stack:
        oid, depth = stack.pop()
        prefix = "| " * depth
        lines.append(f"{prefix}* {_line(nodes[oid])}")
        kids = children.get(oid, [])
        if kids:
            lines.append(f"{prefix}|\\")
        stack.extend((kid, depth + 1) for kid in reversed(kids))
    return lines


def cmd_log(args: argparse.Namespace, console) -> None:
    if getattr(args, "commit", None) or getattr(args, "pr", None):
        from opentine._cli_gitlink import cmd_git

        # --commit/--pr is git integration: read the v3 repo when there is one,
        # otherwise the runs directory, exactly as `tine git log` does.
        if args.repo == "." and not Path(".tine").is_dir():
            args.repo = None
        args.git_command = "log"
        cmd_git(args)
        return
    repo = Repo.open(args.repo)
    graph = args.graph or args.all or args.oneline
    if not graph:
        args.ref = args.ref or "heads/main"
        cmd_repo_log(args, console)
        return
    refs = repo.list_refs()
    if args.all:
        starts = {name: oid for name, oid in refs.items() if name.startswith(RUN_SPACES)}
    else:
        name = args.ref or "heads/main"
        oid = repo.read_ref(name) if not name.startswith("run:") else name
        if oid is None:
            raise KeyError(f"no such ref: {name}")
        starts = {name: oid}
    nodes = collect(repo, starts)
    if getattr(args, "json", False):
        emit({"command": "log", "graph": True, "runs": list(nodes.values())})
        return
    if args.graph:
        for line in graph_lines(nodes):
            console.print(line, highlight=False)
        return
    ordered = sorted(nodes.values(), key=lambda node: node["created_at"], reverse=True)
    for node in ordered[: args.limit or None]:
        console.print(_line(node), highlight=False)


__all__ = ["cmd_log", "collect", "graph_lines"]
