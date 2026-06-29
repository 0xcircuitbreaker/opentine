"""Content-addressed run graph and .tine persistence."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from opentine._canon import (
    FORMAT_VERSION,
    SUPPORTED_VERSIONS,
    _canonical_bytes,
    _integrity_digest,
    _jsonable,
    _redact,
    atomic_write_text,
)
from opentine.budget import Budget, CostBreakdown
from opentine.migrations import migrate_dict


class StepKind(StrEnum):
    think = "think"
    tool = "tool"
    model = "model"
    done = "done"
    error = "error"


class RunStatus(StrEnum):
    running = "running"
    paused = "paused"
    completed = "completed"
    failed = "failed"


@dataclass(frozen=True)
class Step:
    id: str
    parent_ids: list[str]
    kind: StepKind
    inputs: dict[str, Any]
    outputs: dict[str, Any] = field(default_factory=dict)
    model_info: str = ""
    tool_info: dict[str, Any] = field(default_factory=dict)
    error: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    duration: float = 0.0
    cost: float = 0.0
    # token usage {"input": int, "output": int}. Recorded data only — like cost
    # and duration, usage is NOT part of the content-addressed step id.
    usage: dict[str, int] = field(default_factory=dict)

    @property
    def parent_id(self) -> str | None:
        return self.parent_ids[-1] if self.parent_ids else None

    @property
    def short_id(self) -> str:
        return self.id[:12]


@dataclass
class Graph:
    steps: dict[str, Step] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)

    def add(self, step: Step) -> None:
        missing = [pid for pid in step.parent_ids if pid not in self.steps]
        if missing:
            raise ValueError(f"Unknown parent step(s): {', '.join(short_id(m) for m in missing)}")
        if step.id not in self.steps:
            self.order.append(step.id)
        self.steps[step.id] = step

    def ordered(self) -> list[Step]:
        return [self.steps[sid] for sid in self.order if sid in self.steps]

    def roots(self) -> list[Step]:
        return [step for step in self.ordered() if not step.parent_ids]

    def children(self, step_id: str) -> list[Step]:
        sid = self.resolve(step_id)
        return [step for step in self.ordered() if sid in step.parent_ids]

    def resolve(self, ref: str) -> str:
        if ref in self.steps:
            return ref
        matches = [sid for sid in self.steps if sid.startswith(ref)]
        if not matches:
            raise KeyError(f"Unknown step ref: {ref}")
        if len(matches) > 1:
            raise ValueError(f"Ambiguous step ref {ref}: {', '.join(short_id(m) for m in matches)}")
        return matches[0]

    def ancestors(self, step_ref: str) -> list[Step]:
        seen: set[str] = set()
        out: list[Step] = []

        def visit(sid: str) -> None:
            if sid in seen:
                return
            step = self.steps[sid]
            for parent in step.parent_ids:
                visit(parent)
            seen.add(sid)
            out.append(step)

        visit(self.resolve(step_ref))
        return out

    def descendant_closure(self, step_ref: str) -> set[str]:
        root = self.resolve(step_ref)
        out = {root}
        changed = True
        while changed:
            changed = False
            for step in self.ordered():
                if step.id not in out and any(parent in out for parent in step.parent_ids):
                    out.add(step.id)
                    changed = True
        return out


def step_id(
    kind: StepKind,
    inputs: dict[str, Any],
    parent_id: str | None = None,
    *,
    parent_ids: list[str] | None = None,
    outputs: dict[str, Any] | None = None,
    model_info: str = "",
    tool_info: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
) -> str:
    parents = list(parent_ids if parent_ids is not None else ([parent_id] if parent_id else []))
    payload = {
        "kind": kind.value,
        "parent_ids": parents,
        "inputs": inputs,
        "outputs": outputs or {},
        "model_info": model_info,
        "tool_info": tool_info or {},
        "error": error or {},
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def short_id(value: str) -> str:
    return value[:12]


def _normalize_tag(tag: str) -> str:
    return str(tag).strip().lower()


def _normalize_tags(tags: Any) -> list[str]:
    """Lower/strip/dedupe/sort an iterable of tags into a stable list."""
    if isinstance(tags, str):
        tags = [tags]
    seen: set[str] = set()
    out: list[str] = []
    for tag in tags or []:
        norm = _normalize_tag(tag)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return sorted(out)


@dataclass(frozen=True)
class FieldDelta:
    #: which step field changed: inputs/outputs/model_info/tool_info/error/cost/usage/duration
    name: str
    before: Any
    after: Any
    #: for dict fields, the specific sub-keys that differ (empty for scalars)
    changed_keys: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StepChange:
    """Two steps occupying the same lineage position whose content/cost diverged."""

    step_a: Step
    step_b: Step
    fields: list[FieldDelta]


@dataclass
class RunDiff:
    common_ancestor: str | None
    only_a: list[Step]
    only_b: list[Step]
    changed: list[StepChange]


@dataclass(frozen=True)
class IntegrityResult:
    ok: bool
    algorithm: str | None
    expected: str | None
    actual: str | None
    reason: str
    draft: bool = False


@dataclass
class Run:
    run_id: str | None = None
    status: RunStatus = RunStatus.running
    graph: Graph = field(default_factory=Graph)
    refs: dict[str, str] = field(default_factory=dict)
    transcript: list[dict[str, Any]] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)
    policies: dict[str, Any] = field(default_factory=dict)
    cache: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    model_info: str = ""
    system_prompt: str = ""
    user_prompt: str = ""
    format_version: int = FORMAT_VERSION
    tags: list[str] = field(default_factory=list)

    def __init__(self, id: str | None = None, **kwargs: Any):
        self.run_id = kwargs.pop("run_id", id)
        self.status = kwargs.pop("status", RunStatus.running)
        self.graph = kwargs.pop("graph", Graph())
        self.refs = kwargs.pop("refs", {})
        self.transcript = kwargs.pop("transcript", [])
        self.manifest = kwargs.pop("manifest", {})
        self.policies = kwargs.pop("policies", {})
        self.cache = kwargs.pop("cache", {})
        self.metadata = kwargs.pop("metadata", {})
        self.created_at = kwargs.pop("created_at", 0.0)
        self.model_info = kwargs.pop("model_info", "")
        self.system_prompt = kwargs.pop("system_prompt", "")
        self.user_prompt = kwargs.pop("user_prompt", "")
        self.format_version = kwargs.pop("format_version", FORMAT_VERSION)
        tags_kwarg = kwargs.pop("tags", None)
        if kwargs:
            raise TypeError(f"Unexpected Run field(s): {', '.join(kwargs)}")
        self.run_id = self.run_id or step_id(StepKind.model, {"created_at": time.time_ns()})
        self.status = RunStatus(self.status)
        self.graph = self.graph if isinstance(self.graph, Graph) else _graph_from_dict(self.graph)
        self.refs = dict(self.refs)
        self.transcript = list(self.transcript)
        self.manifest = dict(self.manifest)
        self.policies = dict(self.policies)
        self.cache = dict(self.cache)
        self.metadata = dict(self.metadata)
        self.created_at = self.created_at or time.time()
        # Tags come from an explicit kwarg, else from a loaded artifact's
        # metadata.tags. They are normalized (lower, stripped, deduped, sorted).
        raw_tags = tags_kwarg if tags_kwarg is not None else self.metadata.get("tags", [])
        self.tags = _normalize_tags(raw_tags)
        self.refs.setdefault("main", self.graph.order[-1] if self.graph.order else "")

    @property
    def id(self) -> str:
        return self.run_id or ""

    @property
    def steps(self) -> list[Step]:
        return self.graph.ordered()

    def add_tag(self, tag: str) -> bool:
        """Add a tag (normalized). Returns True if it was newly added."""
        norm = _normalize_tag(tag)
        if not norm or norm in self.tags:
            return False
        self.tags = sorted([*self.tags, norm])
        return True

    def remove_tag(self, tag: str) -> bool:
        """Remove a tag (normalized). Returns True if it was present."""
        norm = _normalize_tag(tag)
        if norm not in self.tags:
            return False
        self.tags = [t for t in self.tags if t != norm]
        return True

    def has_tag(self, tag: str) -> bool:
        return _normalize_tag(tag) in self.tags

    def add_step(
        self,
        kind: StepKind,
        inputs: dict[str, Any],
        outputs: dict[str, Any] | None = None,
        parent_id: str | None = None,
        parent_ids: list[str] | None = None,
        duration: float = 0.0,
        cost: float = 0.0,
        model_info: str | None = None,
        tool_info: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
        ref: str = "main",
        usage: dict[str, int] | None = None,
    ) -> Step:
        parents = parent_ids if parent_ids is not None else ([parent_id] if parent_id else [])
        if not parents and self.refs.get(ref):
            parents = [self.refs[ref]]
        parents = [self.graph.resolve(p) for p in parents]
        sid = step_id(
            kind,
            inputs,
            parent_ids=parents,
            outputs=outputs,
            model_info=model_info or self.model_info,
            tool_info=tool_info,
            error=error,
        )
        step = Step(
            id=sid,
            parent_ids=parents,
            kind=StepKind(kind),
            inputs=_jsonable(inputs),
            outputs=_jsonable(outputs or {}),
            model_info=model_info or self.model_info,
            tool_info=_jsonable(tool_info or {}),
            error=_jsonable(error or {}),
            timestamp=time.time(),
            duration=duration,
            cost=cost,
            usage={k: int(v) for k, v in (usage or {}).items()},
        )
        self.graph.add(step)
        self.refs[ref] = sid
        return step

    def get_step(self, sid: str) -> Step | None:
        try:
            return self.graph.steps[self.graph.resolve(sid)]
        except (KeyError, ValueError):
            return None

    def children(self, sid: str) -> list[Step]:
        return self.graph.children(sid)

    def root_steps(self) -> list[Step]:
        return self.graph.roots()

    def ancestors(self, sid: str) -> list[Step]:
        return self.graph.ancestors(sid)

    def common_ancestor(self, a_ref: str, b_ref: str) -> Step | None:
        a = [s.id for s in self.ancestors(a_ref)]
        b = {s.id for s in self.ancestors(b_ref)}
        for sid in reversed(a):
            if sid in b:
                return self.graph.steps[sid]
        return None

    @property
    def total_cost(self) -> float:
        return sum(s.cost for s in self.steps)

    @property
    def total_duration(self) -> float:
        return sum(s.duration for s in self.steps)

    @property
    def total_tokens(self) -> int:
        return sum(int(s.usage.get("input", 0)) + int(s.usage.get("output", 0)) for s in self.steps)

    def cost_breakdown(self) -> CostBreakdown:
        """Aggregate cost/usage by model, step kind, and branch tip."""
        by_model: dict[str, float] = {}
        by_kind: dict[str, float] = {}
        input_tokens = output_tokens = 0
        for step in self.steps:
            by_model[step.model_info] = by_model.get(step.model_info, 0.0) + step.cost
            by_kind[step.kind.value] = by_kind.get(step.kind.value, 0.0) + step.cost
            input_tokens += int(step.usage.get("input", 0))
            output_tokens += int(step.usage.get("output", 0))
        by_ref: dict[str, float] = {}
        for ref, tip in self.refs.items():
            if not tip:  # fresh runs default refs["main"] to "" — skip, never resolve("")
                continue
            try:
                ancestors = self.ancestors(tip)
            except (KeyError, ValueError):
                continue
            by_ref[ref] = sum(a.cost for a in ancestors)
        return CostBreakdown(
            total_cost=self.total_cost,
            total_tokens=input_tokens + output_tokens,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            by_model=by_model,
            by_kind=by_kind,
            by_ref=by_ref,
        )

    def set_budget(
        self,
        *,
        max_cost: float | None = None,
        max_steps: int | None = None,
        max_duration: float | None = None,
        max_usage: int | None = None,
        on_breach: str = "stop",
    ) -> Budget:
        """Attach a spend budget (stored in manifest.budget, inside the digest)."""
        budget = Budget(
            max_cost=max_cost,
            max_steps=max_steps,
            max_duration=max_duration,
            max_usage=max_usage,
            on_breach=on_breach,
        )
        self.manifest["budget"] = budget.to_dict()
        return budget

    def budget(self) -> Budget | None:
        raw = self.manifest.get("budget")
        return Budget.from_dict(raw) if isinstance(raw, dict) and raw else None

    def fork(self, from_step_id: str, new_run_id: str | None = None, branch: str = "main") -> Run:
        fork_point = self.graph.resolve(from_step_id)
        kept = self.ancestors(fork_point)
        graph = Graph()
        for step in kept:
            graph.add(step)
        rid = new_run_id or step_id(StepKind.model, {"fork": self.id, "from": fork_point})
        refs = {branch: fork_point, "fork_point": fork_point}
        # A fork is a new artifact: it does not inherit the parent's tags (fresh
        # labels). Strip any inherited metadata.tags so the forked run starts clean.
        forked_metadata = {k: v for k, v in self.metadata.items() if k != "tags"}
        forked_metadata.update({"forked_from": self.id, "fork_point": fork_point})
        return Run(
            id=rid,
            status=RunStatus.running,
            graph=graph,
            refs=refs,
            transcript=[m for m in self.transcript if m.get("step_id") in graph.steps],
            manifest=dict(self.manifest),
            policies=dict(self.policies),
            metadata=forked_metadata,
            model_info=self.model_info,
            system_prompt=self.system_prompt,
            user_prompt=self.user_prompt,
            tags=[],
        )

    def diff(self, other: Run) -> RunDiff:
        ids_a, ids_b = set(self.graph.steps), set(other.graph.steps)
        tip_a = self.refs.get("main") or (self.steps[-1].id if self.steps else "")
        tip_b = other.refs.get("main") or (other.steps[-1].id if other.steps else "")
        common = None
        if tip_a and tip_b:
            ancestors_a = [s.id for s in self.ancestors(tip_a)]
            ancestors_b = {s.id for s in other.ancestors(tip_b)}
            common = next((sid for sid in reversed(ancestors_a) if sid in ancestors_b), None)

        # Align steps by lineage position + kind. Two steps at the same position
        # with the same kind are "the same logical step"; if their ids differ the
        # content changed, and even when ids match cost/usage/duration may have
        # drifted (those are excluded from the id) — both surface as `changed`.
        pos_a = _position_keys(self)
        pos_b = _position_keys(other)
        by_pos_kind_b = {(pk, str(other.graph.steps[sid].kind)): sid for sid, pk in pos_b.items()}

        changed: list[StepChange] = []
        consumed_a: set[str] = set()
        consumed_b: set[str] = set()
        for sid_a, pk in pos_a.items():
            step_a = self.graph.steps[sid_a]
            sid_b = by_pos_kind_b.get((pk, str(step_a.kind)))
            if sid_b is None:
                continue
            step_b = other.graph.steps[sid_b]
            consumed_a.add(sid_a)
            consumed_b.add(sid_b)
            deltas = (
                _field_deltas(step_a, step_b) if sid_a != sid_b else _drift_deltas(step_a, step_b)
            )
            if deltas:
                changed.append(StepChange(step_a, step_b, deltas))

        only_a = [
            self.graph.steps[sid]
            for sid in self.graph.order
            if sid in ids_a - ids_b and sid not in consumed_a
        ]
        only_b = [
            other.graph.steps[sid]
            for sid in other.graph.order
            if sid in ids_b - ids_a and sid not in consumed_b
        ]
        return RunDiff(common, only_a, only_b, changed)

    def save(self, path: str | Path, *, draft: bool = False, fsync: bool = False) -> Path:
        p = Path(path)
        data = self.to_dict(redact=True)
        if draft:
            # Draft marker is a top-level key (inside the digest) so it is
            # authenticated, not a forgeable metadata breadcrumb. Final saves omit
            # it entirely, so a completed artifact's digest is unaffected.
            data["draft"] = True
            data["metadata"]["autosave"] = {
                "partial": True,
                "step_count": len(self.steps),
                "status": self.status.value,
            }
        data["metadata"]["integrity"] = {
            "algorithm": "sha256",
            "digest": _integrity_digest(data),
        }
        atomic_write_text(p, json.dumps(data, indent=2, sort_keys=True), fsync=fsync)
        return p

    @staticmethod
    def verify_integrity(path_or_data: str | Path | dict[str, Any]) -> IntegrityResult:
        """Verify the SHA-256 digest stored in ``metadata.integrity``."""
        try:
            if isinstance(path_or_data, dict):
                data = path_or_data
            else:
                data = json.loads(Path(path_or_data).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return IntegrityResult(False, None, None, None, "file not found")
        except OSError as exc:
            return IntegrityResult(False, None, None, None, f"read error: {exc}")
        except json.JSONDecodeError as exc:
            return IntegrityResult(False, None, None, None, f"invalid json: {exc.msg}")

        if not isinstance(data, dict):
            return IntegrityResult(False, None, None, None, "artifact root is not an object")

        version = data.get("format_version")
        if version not in SUPPORTED_VERSIONS:
            found = version if version is not None else "missing"
            is_int = isinstance(version, int) and not isinstance(version, bool)
            if is_int and version > FORMAT_VERSION:
                reason = (
                    f"unsupported .tine format_version={found}; "
                    f"written by a newer opentine (max supported {FORMAT_VERSION})"
                )
            else:
                reason = (
                    f"unsupported .tine format_version={found!r}; supported {SUPPORTED_VERSIONS}"
                )
            return IntegrityResult(False, None, None, None, reason)

        metadata = data.get("metadata")
        if not isinstance(metadata, dict):
            return IntegrityResult(False, None, None, None, "missing metadata object")
        integrity = metadata.get("integrity")
        if not isinstance(integrity, dict):
            return IntegrityResult(False, None, None, None, "missing integrity digest")

        algorithm = integrity.get("algorithm")
        expected = integrity.get("digest")
        if algorithm != "sha256":
            return IntegrityResult(False, str(algorithm), expected, None, "unsupported algorithm")
        if not isinstance(expected, str) or len(expected) != 64:
            return IntegrityResult(False, "sha256", expected, None, "malformed digest")
        try:
            int(expected, 16)
        except ValueError:
            return IntegrityResult(False, "sha256", expected, None, "malformed digest")

        actual = _integrity_digest(data)
        ok = actual == expected
        return IntegrityResult(
            ok,
            "sha256",
            expected,
            actual,
            "ok" if ok else "digest mismatch",
            draft=bool(data.get("draft")),
        )

    @classmethod
    def load(cls, path: str | Path) -> Run:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        version = data.get("format_version")
        if version not in SUPPORTED_VERSIONS:
            found = version if version is not None else "missing"
            raise ValueError(
                f"Unsupported .tine format_version={found!r}; supported {SUPPORTED_VERSIONS}"
            )
        if version != FORMAT_VERSION:
            data = migrate_dict(data, FORMAT_VERSION)
        return _run_from_dict(data)

    def pause(self, path: str | Path) -> Path:
        self.status = RunStatus.paused
        return self.save(path)

    @classmethod
    def resume(cls, path: str | Path) -> Run:
        run = cls.load(path)
        run.status = RunStatus.running
        return run

    def to_dict(self, *, redact: bool = False) -> dict[str, Any]:
        data = {
            "format_version": self.format_version,
            "run_id": self.id,
            "created_at": self.created_at,
            "status": self.status.value,
            "graph": {
                "steps": {sid: _step_to_dict(step) for sid, step in self.graph.steps.items()},
                "order": list(self.graph.order),
            },
            "refs": dict(self.refs),
            "transcript": list(self.transcript),
            "manifest": dict(self.manifest),
            "policies": dict(self.policies),
            "cache": dict(self.cache),
            "metadata": {
                **self.metadata,
                "model_info": self.model_info,
                "system_prompt": self.system_prompt,
                "user_prompt": self.user_prompt,
            },
        }
        # Tags live in metadata (outside the integrity digest, so re-tagging never
        # invalidates a digest/signature). Emit only when non-empty so v1 artifacts
        # with no tags re-save without spurious fields.
        if self.tags:
            data["metadata"]["tags"] = list(self.tags)
        else:
            data["metadata"].pop("tags", None)
        return _redact(data) if redact else data


def _position_keys(run: Run) -> dict[str, str]:
    """Map each step id to a lineage position key like '0', '0.0', '0.1.0'.

    The key is the path from a root through primary parents (parent_ids[0]) with
    siblings ordered by id, so the same logical position is stable across runs
    even when content (and thus the step id) changes. Iterative to avoid hitting
    the recursion limit on deep linear chains.
    """
    children_of: dict[str | None, list[str]] = {}
    for sid in run.graph.order:
        step = run.graph.steps[sid]
        primary = step.parent_ids[0] if step.parent_ids else None
        children_of.setdefault(primary, []).append(sid)
    keys: dict[str, str] = {}
    stack = [(root, str(i)) for i, root in enumerate(sorted(children_of.get(None, [])))]
    while stack:
        sid, key = stack.pop()
        keys[sid] = key
        for i, child in enumerate(sorted(children_of.get(sid, []))):
            stack.append((child, f"{key}.{i}"))
    return keys


_DIFF_FIELDS = ("inputs", "outputs", "model_info", "tool_info", "error")


def _dict_changed_keys(a: Any, b: Any) -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
    return []


def _drift_deltas(a: Step, b: Step) -> list[FieldDelta]:
    """Deltas for fields excluded from the step id (cost, usage).

    These surface even when two steps share an id — e.g. a cached replay that
    re-derived identical content at a different price. Duration is intentionally
    omitted as wall-clock noise.
    """
    deltas: list[FieldDelta] = []
    if abs(a.cost - b.cost) > 1e-12:
        deltas.append(FieldDelta("cost", a.cost, b.cost))
    if a.usage != b.usage:
        deltas.append(FieldDelta("usage", a.usage, b.usage, _dict_changed_keys(a.usage, b.usage)))
    return deltas


def _field_deltas(a: Step, b: Step) -> list[FieldDelta]:
    deltas: list[FieldDelta] = []
    for name in _DIFF_FIELDS:
        va, vb = getattr(a, name), getattr(b, name)
        if va != vb:
            deltas.append(FieldDelta(name, va, vb, _dict_changed_keys(va, vb)))
    deltas.extend(_drift_deltas(a, b))
    return deltas


def _step_to_dict(step: Step) -> dict[str, Any]:
    data = {
        "id": step.id,
        "parent_ids": list(step.parent_ids),
        "kind": step.kind.value,
        "inputs": step.inputs,
        "outputs": step.outputs,
        "model_info": step.model_info,
        "tool_info": step.tool_info,
        "error": step.error,
        "timestamp": step.timestamp,
        "duration": step.duration,
        "cost": step.cost,
    }
    # Emit usage only when present so v1 golden artifacts re-save without it.
    if step.usage:
        data["usage"] = {k: int(v) for k, v in step.usage.items()}
    return data


def _step_from_dict(data: dict[str, Any]) -> Step:
    parents = data.get("parent_ids")
    if parents is None:
        parent = data.get("parent_id")
        parents = [parent] if parent else []
    return Step(
        id=data["id"],
        parent_ids=list(parents),
        kind=StepKind(data["kind"]),
        inputs=dict(data.get("inputs") or {}),
        outputs=dict(data.get("outputs") or {}),
        model_info=data.get("model_info", ""),
        tool_info=dict(data.get("tool_info") or {}),
        error=dict(data.get("error") or {}),
        timestamp=float(data.get("timestamp") or 0.0),
        duration=float(data.get("duration") or 0.0),
        cost=float(data.get("cost") or 0.0),
        usage={k: int(v) for k, v in (data.get("usage") or {}).items()},
    )


def _graph_from_dict(data: dict[str, Any]) -> Graph:
    graph = Graph()
    steps = data.get("steps", {})
    for sid in data.get("order", list(steps)):
        graph.add(_step_from_dict(steps[sid]))
    return graph


def _run_from_dict(data: dict[str, Any]) -> Run:
    run = Run(
        run_id=data["run_id"],
        status=RunStatus(data.get("status", "running")),
        graph=_graph_from_dict(data.get("graph", {})),
        refs=data.get("refs", {}),
        transcript=data.get("transcript", []),
        manifest=data.get("manifest", {}),
        policies=data.get("policies", {}),
        cache=data.get("cache", {}),
        metadata=data.get("metadata", {}),
        created_at=data.get("created_at", 0.0),
        format_version=data.get("format_version", FORMAT_VERSION),
    )
    run.model_info = run.manifest.get("model", {}).get("name", run.metadata.get("model_info", ""))
    run.system_prompt = run.metadata.get("system_prompt", "")
    run.user_prompt = run.metadata.get("user_prompt", "")
    return run
