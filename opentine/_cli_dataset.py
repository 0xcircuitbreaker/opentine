"""``tine dataset add|import|export|show``: eval datasets as JSON Lines (0.45)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from opentine._cli_errors import ERROR, NOT_FOUND, USAGE, fail

FORMATS = ("jsonl", "hf")


def add_dataset_parser(sub: Any) -> None:
    dataset = sub.add_parser("dataset", help="Build eval datasets: add, import, export, show")
    verbs = dataset.add_subparsers(dest="dataset_command", required=True)
    add = verbs.add_parser("add", help="Append an item to a JSONL dataset (created if absent)")
    add.add_argument("dataset", metavar="DATASET.jsonl")
    add.add_argument("--from-run", required=True, metavar="RUN", help="Run whose prompt/answer")
    add.add_argument("--repo", help="Resolve RUN in this v3 repository")
    add.add_argument("--id", dest="item_id", metavar="ID", help="Item id (default: from the run)")
    add.add_argument("--expected", metavar="TEXT", help="The reference answer for scorers")
    importer = verbs.add_parser("import", help="Read a JSONL file or a local HF dataset folder")
    importer.add_argument("source", metavar="SRC")
    exporter = verbs.add_parser("export", help="Write a dataset as JSONL or an HF folder")
    exporter.add_argument("dataset", metavar="DATASET.jsonl")
    for verb in (importer, exporter):
        verb.add_argument("--format", choices=FORMATS, default="jsonl")
        verb.add_argument("--out", required=True, metavar="PATH")
        verb.add_argument("--split", default="train", help="HF split name (default: train)")
    for name in ("id", "input", "expected"):
        importer.add_argument(f"--{name}-field", default=name, help=f"HF column for {name}")
    show = verbs.add_parser("show", help="Item count and digest of a dataset")
    show.add_argument("dataset", metavar="DATASET.jsonl")
    for verb in (add, importer, exporter, show):
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _load_run(name: str, repo: str | None) -> tuple[Any, str]:
    from opentine._cli_common import _find_run, _runs_dir
    from opentine.graph import Run

    if repo:
        from opentine._git_link_runs import open_catalog

        catalog = open_catalog(repo, _runs_dir())
        try:
            run = catalog.load(name)
        except Exception as exc:  # noqa: BLE001 - any unreadable run is "not found"
            fail(f"no run {name!r} in {repo}: {exc}", NOT_FOUND)
        return run, catalog.canonical(run.id)
    path = _find_run(name)
    if path is None:
        fail(f"no run {name!r}", NOT_FOUND)
    run = Run.load(path)
    return run, run.id


def _add(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._eval_dataset import read_jsonl, run_item, write_jsonl

    path = Path(args.dataset)
    items = read_jsonl(path) if path.exists() else []
    run, name = _load_run(args.from_run, args.repo)
    item = run_item(run, name, item_id=args.item_id)
    if args.expected is not None:
        item["expected"] = args.expected
    if any(existing["id"] == item["id"] for existing in items):
        fail(f"{path} already holds an item {item['id']!r}; pass --id", USAGE)
    write_jsonl(path, [*items, item])
    return {"dataset": str(path), "item": item["id"], "run": name, "items": len(items) + 1}


def _import(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._eval_dataset import import_hf, read_jsonl, write_jsonl

    if args.format == "hf":
        items = import_hf(
            Path(args.source),
            split=args.split,
            id_field=args.id_field,
            input_field=args.input_field,
            expected_field=args.expected_field,
        )
    else:
        items = read_jsonl(Path(args.source))
    write_jsonl(Path(args.out), items)
    return {"out": str(args.out), "items": len(items)}


def _export(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._eval_dataset import export_hf, read_jsonl, write_jsonl

    items = read_jsonl(Path(args.dataset))
    if args.format == "hf":
        export_hf(Path(args.out), items, split=args.split)
    else:
        write_jsonl(Path(args.out), items)
    return {"out": str(args.out), "format": args.format, "items": len(items)}


def _show(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._eval_dataset import dataset_digest, read_jsonl

    items = read_jsonl(Path(args.dataset))
    scored = sum(1 for item in items if "output" in item)
    return {"dataset": str(args.dataset), "items": len(items), "with_output": scored,
            "digest": dataset_digest(items)}  # fmt: skip


def cmd_dataset(args: argparse.Namespace) -> None:
    from opentine._cli_common import console
    from opentine._cli_json import emit
    from opentine._eval_dataset import DatasetError

    verb = args.dataset_command
    handler = {"add": _add, "import": _import, "export": _export, "show": _show}[verb]
    try:
        row = handler(args)
    except (DatasetError, OSError, ValueError) as exc:
        fail(exc, ERROR, prefix=f"dataset {verb}: ", cause=exc)
    if args.json:
        emit({"command": f"dataset {verb}", **row})
        return
    console.print(json.dumps(row, indent=2, sort_keys=True), highlight=False, markup=False)


COMMANDS = {"dataset": cmd_dataset}

__all__ = ["COMMANDS", "add_dataset_parser", "cmd_dataset"]
