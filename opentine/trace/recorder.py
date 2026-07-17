"""Live append/fork/evaluate/promote workflow for agent-facing v3 runs."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from typing import Any

from opentine.trace._record_event import SpanMap, json_blob, put_trace_event, span_key
from opentine.trace.capture import code_manifest, environment_manifest
from opentine.trace.schema import TraceEvent

MAX_RECORDED_EVENTS = 3_000


class Recorder:
    def __init__(self, repo, run_id: str, ref: str, span_map: SpanMap | None = None):
        self.repo = repo
        self.run_id = run_id
        self.ref = ref
        self.span_map = dict(span_map or {})

    @classmethod
    def start(
        cls,
        repo,
        *,
        ref: str = "heads/main",
        prompt: str = "",
        system: str = "",
        code: dict[str, Any] | None = None,
        environment: dict[str, Any] | None = None,
        policy: dict[str, Any] | None = None,
        budget: dict[str, Any] | None = None,
        pricing: dict[str, Any] | None = None,
        capture: bool = True,
    ) -> Recorder:
        captured_code = code if code is not None else code_manifest() if capture else {}
        manifests = {
            "budget": json_blob(repo, budget or {}),
            "code": json_blob(repo, captured_code),
            "environment": json_blob(
                repo,
                environment
                if environment is not None
                else environment_manifest()
                if capture
                else {},
            ),
            "policy": json_blob(repo, policy or {}),
            "pricing": json_blob(repo, pricing or {}),
        }
        payload = {
            "created_at": time.time(),
            "events": [],
            "manifests": manifests,
            "prompt_blob": repo.put("blob", prompt.encode()),
            "roots": [],
            "session_id": str(uuid.uuid4()),
            "status": "running",
            "system_blob": repo.put("blob", system.encode()),
            "tips": [],
        }
        run_id = repo.put("run", payload)
        repo.update_ref(ref, run_id, expected_old=repo.read_ref(ref))
        return cls(repo, run_id, ref)

    @classmethod
    def resume(cls, repo, run_or_ref: str, *, ref: str | None = None) -> Recorder:
        try:
            resolved_ref = repo.read_ref(run_or_ref)
        except ValueError:
            resolved_ref = None
        run_id = resolved_ref or run_or_ref
        payload = repo.get(run_id).payload()
        if repo.get(run_id).object_type != "run":
            raise ValueError("recorder resume target is not a run")
        selected_ref = ref or (run_or_ref if resolved_ref else "heads/main")
        span_map: SpanMap = {}
        for event in payload.get("events") or []:
            event_payload = repo.get(event).payload()
            span_id = event_payload.get("span_id")
            if span_id is None:
                continue
            key = span_key(event_payload.get("trace_id", ""), span_id)
            if key in span_map:
                raise ValueError(f"duplicate span ID within trace: {key[1]!r}")
            span_map[key] = event
        return cls(repo, run_id, selected_ref, span_map)

    @property
    def payload(self) -> dict[str, Any]:
        return self.repo.get(self.run_id).payload()

    @staticmethod
    def _capacity(run: dict[str, Any], incoming: int) -> None:
        if len(run.get("events") or []) + incoming > MAX_RECORDED_EVENTS:
            raise ValueError(f"Recorder runs are limited to {MAX_RECORDED_EVENTS} events")

    def append(self, event: TraceEvent, *, chain_if_parentless: bool = True) -> str:
        run = self.payload
        self._capacity(run, 1)
        key = span_key(event.trace_id, event.span_id)
        if key in self.span_map:
            raise ValueError(f"duplicate span ID within trace: {key[1]!r}")
        fallback = None
        if not event.parent_span_id and chain_if_parentless and run.get("tips"):
            fallback = run["tips"][-1]
        event_id, parents = put_trace_event(
            self.repo, event, self.span_map, parent_fallback=fallback
        )
        updated = dict(run)
        updated["events"] = [*(run.get("events") or []), event_id]
        roots = list(run.get("roots") or [])
        updated["roots"] = roots if parents else [*roots, event_id]
        old_tips = [tip for tip in run.get("tips") or [] if tip not in parents]
        updated["tips"] = [*old_tips, event_id]
        next_run = self.repo.put("run", updated)
        self.repo.update_ref(self.ref, next_run, expected_old=self.run_id)
        self.run_id = next_run
        self.span_map[key] = event_id
        return event_id

    def import_events(self, events: list[TraceEvent]) -> list[str]:
        run = self.payload
        self._capacity(run, len(events))
        by_span: dict[tuple[str, str], int] = {}
        for index, event in enumerate(events):
            key = span_key(event.trace_id, event.span_id)
            if key in self.span_map or key in by_span:
                raise ValueError(f"duplicate span ID within trace: {key[1]!r}")
            by_span[key] = index
        children: dict[int, list[int]] = defaultdict(list)
        degrees = [0] * len(events)
        for index, event in enumerate(events):
            dependencies = {span_key(event.trace_id, value) for value in event.causal_span_ids}
            if event.parent_span_id is not None:
                dependencies.add(span_key(event.trace_id, event.parent_span_id))
            for dependency in dependencies:
                parent = by_span.get(dependency)
                if parent is not None:
                    children[parent].append(index)
                    degrees[index] += 1
        ready = deque(index for index, degree in enumerate(degrees) if degree == 0)
        order: list[int] = []
        while ready:
            parent = ready.popleft()
            order.append(parent)
            for child in children[parent]:
                degrees[child] -= 1
                if degrees[child] == 0:
                    ready.append(child)
        if len(order) != len(events):
            raise ValueError("trace parent/causal dependency cycle")
        result = [""] * len(events)
        working_map = dict(self.span_map)
        ordered_ids: list[str] = []
        new_roots: list[str] = []
        parented: set[str] = set()
        for index in order:
            event = events[index]
            event_id, parents = put_trace_event(self.repo, event, working_map)
            result[index] = event_id
            ordered_ids.append(event_id)
            working_map[span_key(event.trace_id, event.span_id)] = event_id
            if parents:
                parented.update(parents)
            else:
                new_roots.append(event_id)
        if not ordered_ids:
            return result
        updated = dict(run)
        updated["events"] = [*(run.get("events") or []), *ordered_ids]
        updated["roots"] = [*(run.get("roots") or []), *new_roots]
        tips = [*(run.get("tips") or []), *ordered_ids]
        updated["tips"] = [event_id for event_id in tips if event_id not in parented]
        next_run = self.repo.put("run", updated)
        self.repo.update_ref(self.ref, next_run, expected_old=self.run_id)
        self.run_id = next_run
        self.span_map = working_map
        return result

    def finalize(self, status: str = "completed") -> str:
        payload = dict(self.payload)
        payload["status"] = status
        payload["finished_at"] = time.time()
        next_run = self.repo.put("run", payload)
        self.repo.update_ref(self.ref, next_run, expected_old=self.run_id)
        self.run_id = next_run
        return next_run

    def fork(
        self,
        from_event: str,
        *,
        ref: str,
        model: str | None = None,
        prompt: str | None = None,
        policy: dict[str, Any] | None = None,
    ) -> Recorder:
        fork_id = self.repo.fork(
            self.run_id,
            from_event,
            overrides={"model": model, "policy": policy, "prompt": prompt},
            ref=ref,
        )
        return Recorder.resume(self.repo, fork_id, ref=ref)

    def evaluate(
        self,
        scores: dict[str, float],
        *,
        evaluator: str,
        evidence_ids: list[str] | None = None,
    ) -> str:
        return self.repo.attest(
            self.run_id,
            {"kind": "evaluation", "scores": scores},
            signer=evaluator,
            evidence_ids=evidence_ids,
        )

    def approve(self, *, approver: str, note: str = "") -> str:
        return self.repo.attest(
            self.run_id,
            {"kind": "approval", "note": note},
            signer=approver,
        )

    def promote(self, name: str, *, expected_old: str | None = None) -> None:
        self.repo.promote(self.run_id, name, expected_old=expected_old)
