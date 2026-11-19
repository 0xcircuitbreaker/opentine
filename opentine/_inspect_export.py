"""OpenTine runs -> an Inspect log (0.64), the inverse of :mod:`opentine._inspect_import`.

Every run under one ``heads/inspect/<task>-<eval>/`` prefix becomes one sample,
in the order the import recorded them. Sample ids (with their JSON type),
epochs, targets and scores come back exactly from the ``inspect`` run
annotation; messages are rebuilt from the steps. Output is an ``EvalLog`` JSON
object (``version`` 2) or a ``.eval`` zip (``header.json`` +
``samples/<id>_epoch_<n>.json``) written with fixed timestamps so the same runs
always give the same bytes.
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any

from opentine._inspect_import import ANNOTATION_KEY, REF_ROOT
from opentine.repository._annotations import load_run_annotation

ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def prefixes(repo: Any) -> list[str]:
    """Every imported eval's ref prefix in *repo*."""
    seen = set()
    for name in repo.list_refs():
        if name.startswith(REF_ROOT) and name.count("/") >= 3:
            seen.add(name.rsplit("/", 1)[0] + "/")
    return sorted(seen)


def _messages(run: Any) -> list[dict[str, Any]]:
    out = []
    for step in run.steps:
        for side in (step.inputs, step.outputs):
            message = side.get("message") if isinstance(side, dict) else None
            if isinstance(message, dict):
                out.append(message)
    return out


def collect(repo: Any, prefix: str | None = None) -> dict[str, Any]:
    """The Inspect ``EvalLog`` dict for the eval under *prefix* (the only one if None)."""
    found = prefixes(repo)
    if prefix is None:
        if len(found) != 1:
            listed = ", ".join(found) or "none"
            raise ValueError(f"name one imported eval with --prefix (found: {listed})")
        prefix = found[0]
    if not prefix.endswith("/"):
        prefix += "/"
    if not prefix.startswith(REF_ROOT):
        prefix = REF_ROOT + prefix
    refs = sorted((name, oid) for name, oid in repo.list_refs().items() if name.startswith(prefix))
    if not refs:
        raise ValueError(f"no imported Inspect samples under {prefix}")
    samples, shared = [], None
    for _name, oid in refs:
        run = repo.load_run(oid)
        metadata, _tags = load_run_annotation(repo, run.id)
        claim = metadata.get(ANNOTATION_KEY)
        if not isinstance(claim, dict):
            raise ValueError(f"run {run.id} carries no inspect annotation")
        shared = shared or claim
        samples.append((claim.get("index", len(samples)), {
            "id": claim["sample_id"], "epoch": claim["epoch"], "input": claim["input"],
            "target": claim["target"], "messages": _messages(run), "output": claim["output"],
            "scores": claim["scores"], "metadata": claim["metadata"],
        }))  # fmt: skip
    samples.sort(key=lambda pair: pair[0])
    log = {"version": shared.get("version", 2), "status": shared.get("status", "success"),
           "eval": shared["eval"]}  # fmt: skip
    if shared.get("results") is not None:
        log["results"] = shared["results"]
    log["samples"] = [sample for _index, sample in samples]
    return log


def to_json_bytes(log: dict[str, Any]) -> bytes:
    return (json.dumps(log, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def to_eval_bytes(log: dict[str, Any]) -> bytes:
    """A deterministic ``.eval`` zip of *log*."""
    header = {key: value for key, value in log.items() if key != "samples"}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:

        def put(name: str, value: Any) -> None:
            info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, json.dumps(value, ensure_ascii=False).encode("utf-8"))

        put("header.json", header)
        for sample in log["samples"]:
            put(f"samples/{sample['id']}_epoch_{sample['epoch']}.json", sample)
    return buffer.getvalue()


__all__ = ["collect", "prefixes", "to_eval_bytes", "to_json_bytes"]
