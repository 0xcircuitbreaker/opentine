"""Eval datasets: JSON Lines of items, a digest, and Hugging Face-style folders (0.45).

A dataset is a JSONL file, one item per line::

    {"id": "q-0001", "input": ..., "expected": ..., "output": ..., "run": "<run>",
     "metadata": {...}}

``id`` and ``input`` are required; ``output`` and ``run`` say what an eval
scores (``tine dataset add --from-run`` fills both). An item's digest is
``sha256:`` over JCS of the item; the dataset's is ``sha256:`` over
``opentine.dataset.v1:`` + JCS of the list of item digests, so a verdict binds
the exact bytes it scored.

Hugging Face import and export are offline and file-based: a folder holding
``<split>.jsonl`` files (or ``data/<split>*.jsonl``) with arbitrary columns,
mapped onto ``id``/``input``/``expected`` by column name. Parquet is not read.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine._eval_verdict import NAME_RE
from opentine.kernel import canonical_json

DOMAIN = b"opentine.dataset.v1:"
ITEM_FIELDS = ("id", "input", "expected", "output", "run", "metadata")
MAX_ITEMS = 1_000_000


class DatasetError(ValueError):
    """A dataset that cannot be read or written as asked."""


def item_digest(item: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(item)).hexdigest()


def dataset_digest(items: list[dict[str, Any]]) -> str:
    digests = [item_digest(item) for item in items]
    return "sha256:" + hashlib.sha256(DOMAIN + canonical_json(digests)).hexdigest()


def check_item(item: Any, where: str) -> dict[str, Any]:
    if not isinstance(item, dict) or "id" not in item or "input" not in item:
        raise DatasetError(f"{where}: an item is an object with at least id and input")
    if set(item) - set(ITEM_FIELDS):
        raise DatasetError(f"{where}: unknown item field(s) {sorted(set(item) - set(ITEM_FIELDS))}")
    if not isinstance(item["id"], str) or not NAME_RE.fullmatch(item["id"]):
        raise DatasetError(f"{where}: id must be 1..256 safe characters")
    if "run" in item and not (isinstance(item["run"], str) and NAME_RE.fullmatch(item["run"])):
        raise DatasetError(f"{where}: run must be a run name")
    return item


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Every item of a JSONL dataset; ids must be unique."""
    items: list[dict[str, Any]] = []
    try:
        lines = Path(path).read_text("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise DatasetError(f"cannot read dataset {path}: {exc}") from exc
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError as exc:
            raise DatasetError(f"{path}:{number}: not JSON: {exc}") from exc
        items.append(check_item(value, f"{path}:{number}"))
        if len(items) > MAX_ITEMS:
            raise DatasetError(f"{path}: more than {MAX_ITEMS} items")
    seen: set[str] = set()
    for item in items:
        if item["id"] in seen:
            raise DatasetError(f"{path}: duplicate item id {item['id']!r}")
        seen.add(item["id"])
    return items


def write_jsonl(path: Path, items: list[dict[str, Any]]) -> None:
    from opentine._canon import atomic_write_text

    lines = [json.dumps(item, sort_keys=True, ensure_ascii=False) for item in items]
    atomic_write_text(Path(path), "".join(f"{line}\n" for line in lines))


def _text(mapping: Any) -> str:
    if isinstance(mapping, str):
        return mapping
    if isinstance(mapping, dict):
        for key in ("text", "content", "prompt", "message", "result", "output", "answer"):
            if isinstance(mapping.get(key), str):
                return mapping[key]
    return ""


def run_item(run: Any, run_name: str, *, item_id: str | None = None) -> dict[str, Any]:
    """A dataset item from a recorded run: its prompt as input, its last answer as output."""
    steps = list(run.steps)
    prompt = run.user_prompt or (_text(steps[0].inputs) if steps else "")
    answers = [_text(step.outputs) for step in steps if step.outputs]
    output = next((text for text in reversed(answers) if text), "")
    return {"id": item_id or run_name.replace("sha256:", "")[:24], "input": prompt,
            "output": output, "run": run_name}  # fmt: skip


def _hf_files(folder: Path, split: str) -> list[Path]:
    found = sorted(folder.glob(f"{split}.jsonl")) + sorted(folder.glob(f"data/{split}*.jsonl"))
    if not found:
        raise DatasetError(
            f"{folder}: no {split}.jsonl or data/{split}*.jsonl (Parquet unsupported)"
        )
    return found


def import_hf(
    folder: Path,
    *,
    split: str = "train",
    id_field: str = "id",
    input_field: str = "input",
    expected_field: str = "expected",
) -> list[dict[str, Any]]:
    """Items from a local Hugging Face dataset folder of JSON Lines splits."""
    items: list[dict[str, Any]] = []
    for path in _hf_files(Path(folder), split):
        for number, line in enumerate(path.read_text("utf-8").splitlines(), 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict) or input_field not in row:
                raise DatasetError(f"{path}:{number}: no {input_field!r} column")
            ident = row.get(id_field, f"{split}-{len(items):06d}")
            item = {"id": str(ident), "input": row[input_field]}
            if expected_field in row:
                item["expected"] = row[expected_field]
            rest = {
                k: v for k, v in row.items() if k not in (id_field, input_field, expected_field)
            }
            if rest:
                item["metadata"] = rest
            items.append(check_item(item, f"{path}:{number}"))
    return items


def export_hf(folder: Path, items: list[dict[str, Any]], *, split: str = "train") -> Path:
    """A Hugging Face-loadable folder: ``data/<split>.jsonl``, ``dataset_info.json``, a card."""
    from opentine._canon import atomic_write_text

    folder = Path(folder)
    (folder / "data").mkdir(parents=True, exist_ok=True)
    write_jsonl(folder / "data" / f"{split}.jsonl", items)
    info = {"description": "Exported by tine dataset export", "splits": {split: len(items)},
            "opentine_dataset_digest": dataset_digest(items)}  # fmt: skip
    atomic_write_text(folder / "dataset_info.json", json.dumps(info, indent=2, sort_keys=True))
    card = (
        "---\nconfigs:\n- config_name: default\n  data_files:\n"
        f"  - split: {split}\n    path: data/{split}.jsonl\n---\n"
        "# Dataset exported by opentine\n"
    )
    atomic_write_text(folder / "README.md", card)
    return folder


__all__ = [
    "DatasetError",
    "check_item",
    "dataset_digest",
    "export_hf",
    "import_hf",
    "item_digest",
    "read_jsonl",
    "run_item",
    "write_jsonl",
]
