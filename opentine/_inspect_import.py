"""Inspect log -> OpenTine runs (0.64): one run per sample, kept exactly enough to export.

Mapping (no new object kinds):

* each sample (id, epoch) becomes one ordinary run on
  ``heads/inspect/<task>-<eval>/s<index>``; its messages become steps (the
  whole Inspect message rides in the step's ``inputs.message`` for user, system
  and tool turns, ``outputs.message`` for assistant turns);
* the eval's sandbox config becomes the run's first step, a ``policy`` step
  whose ``inputs["inspect.sandbox"]`` is the config as written: step evidence of
  the environment the sample ran in;
* the sample id (string or integer, type kept), epoch, target, raw scores and
  the eval header live in the run annotation under ``inspect`` (a claim
  convention, documented in docs/INSPECT.md);
* with a signing key, each scorer's scores become a signed eval folder of
  ``tine-eval-verdict/1`` objects (:mod:`opentine._inspect_verdicts`).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from opentine._import_write import annotate, record
from opentine.trace.schema import TraceEvent

SOURCE_FORMAT = "inspect"
REF_ROOT = "heads/inspect/"
ANNOTATION_KEY = "inspect"
_SLUG = re.compile(r"[^a-z0-9_-]+")


def slug(text: str, limit: int = 48) -> str:
    return (_SLUG.sub("-", str(text).lower()).strip("-") or "x")[:limit]


def eval_key(head: dict[str, Any]) -> str:
    """A stable short name for one eval: its ``eval_id``, else a digest of the header."""
    ident = head.get("eval_id") or head.get("run_id")
    if isinstance(ident, str) and ident:
        return slug(ident, 24)
    digest = hashlib.sha256(json.dumps(head, sort_keys=True, default=str).encode()).hexdigest()
    return digest[:16]


def ref_prefix(head: dict[str, Any]) -> str:
    return f"{REF_ROOT}{slug(head['task'])}-{eval_key(head)}/"


def _events(sample: dict[str, Any], head: dict[str, Any], trace: str) -> list[TraceEvent]:
    model = head.get("model") if isinstance(head.get("model"), str) else ""
    out: list[TraceEvent] = []

    def add(kind: str, actor: str, **fields: Any) -> None:
        index = len(out)
        out.append(TraceEvent(kind=kind, timestamp=float(index), trace_id=trace,
                              span_id=f"{index:016x}", actor=actor, **fields))  # fmt: skip

    sandbox = head.get("sandbox")
    if sandbox:
        add("policy", "inspect:sandbox", inputs={"inspect.sandbox": sandbox})
    for message in sample["messages"]:
        role = message.get("role")
        if role == "assistant":
            add("model", "assistant", model=model, outputs={"message": message})
        elif role == "tool":
            name = message.get("function") if isinstance(message.get("function"), str) else ""
            add("tool", name or "tool", inputs={"message": message})
        else:
            add("human", role if isinstance(role, str) else "user", inputs={"message": message})
    if not sample["messages"]:
        add("human", "user", inputs={"inspect.input": sample["input"]})
    return out


def _header(head: dict[str, Any]) -> dict[str, Any]:
    keep = ("eval_id", "run_id", "created", "task", "task_id", "task_version", "model",
            "dataset", "sandbox", "task_args", "config", "revision", "packages",
            "metadata")  # fmt: skip
    return {name: head[name] for name in keep if name in head}


def import_log(repo: Any, log: dict[str, Any]) -> dict[str, Any]:
    """Record every sample of a parsed log (:func:`opentine._inspect_log.parse_log`)."""
    head = log["eval"]
    prefix = ref_prefix(head)
    taken = [name for name in repo.list_refs() if name.startswith(prefix)]
    if taken:
        raise ValueError(f"{prefix} already holds an import of this eval; nothing written")
    rows = []
    shared = {"eval": _header(head), "status": log["status"], "version": log["version"],
              "results": log["results"]}  # fmt: skip
    for index, sample in enumerate(log["samples"]):
        trace = hashlib.sha256(f"{prefix}{index}".encode()).hexdigest()[:32]
        ref = f"{prefix}s{index:06d}"
        run_id = record(repo, _events(sample, head, trace), ref, None, SOURCE_FORMAT)
        claim = {
            "sample_id": sample["id"], "epoch": sample["epoch"], "index": index,
            "input": sample["input"], "target": sample["target"], "scores": sample["scores"],
            "output": sample["output"], "metadata": sample["metadata"], **shared,
        }  # fmt: skip
        annotate(repo, run_id, {ANNOTATION_KEY: claim})
        rows.append({"sample_id": sample["id"], "epoch": sample["epoch"], "run": run_id,
                     "ref": ref, "scorers": sorted(sample["scores"])})  # fmt: skip
    return {"task": head["task"], "eval_id": head.get("eval_id"), "ref_prefix": prefix,
            "samples": rows}  # fmt: skip


__all__ = ["ANNOTATION_KEY", "REF_ROOT", "SOURCE_FORMAT", "import_log", "ref_prefix", "slug"]
