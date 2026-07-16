"""Live append/fork/evaluate/promote workflow for agent-facing v3 runs."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from typing import Any

from opentine._canon import _redact
from opentine._jsonsafe import json_safe
from opentine.kernel import canonical_json
from opentine.redaction import redact_value
from opentine.trace.capture import code_manifest, environment_manifest
from opentine.trace.schema import TraceEvent


def _json_blob(repo, value: Any) -> str:
    redacted = redact_value(_redact(json_safe(value)))
    return repo.put("blob", canonical_json(redacted), redact=False)


class Recorder:
    def __init__(self, repo, run_id: str, ref: str, span_map: dict[str, str] | None = None):
        self.repo = repo
        self.run_id = run_id
        self.ref = ref
        self.span_map = span_map or {}

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
            "budget": _json_blob(repo, budget or {}),
            "code": _json_blob(repo, captured_code),
            "environment": _json_blob(
                repo,
                environment
                if environment is not None
                else environment_manifest()
                if capture
                else {},
            ),
            "policy": _json_blob(repo, policy or {}),
            "pricing": _json_blob(repo, pricing or {}),
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
        span_map: dict[str, str] = {}
        for event in payload.get("events") or []:
            span_id = repo.get(event).payload().get("span_id")
            if span_id:
                span_map[str(span_id)] = event
        return cls(repo, run_id, selected_ref, span_map)

    @property
    def payload(self) -> dict[str, Any]:
        return self.repo.get(self.run_id).payload()

    def append(self, event: TraceEvent, *, chain_if_parentless: bool = True) -> str:
        run = self.payload
        parent = self.span_map.get(str(event.parent_span_id or ""))
        if parent is None and not event.parent_span_id and chain_if_parentless and run.get("tips"):
            parent = run["tips"][-1]
        parents = [parent] if parent else []
        causal = list(
            dict.fromkeys(
                self.span_map[key]
                for span in event.causal_span_ids
                if (key := str(span)) in self.span_map
            )
        )
        billing = _redact(json_safe(event.billing))
        cost = event.cost
        if cost is None and isinstance(billing, dict):
            cost = billing.get("known_subtotal_usd", 0)
        payload = {
            "actor": str(event.actor),
            "attributes": _redact(json_safe(event.attributes)),
            "billing": billing,
            "causal_ids": causal,
            "cost": json_safe(cost or 0),
            "duration": json_safe(event.duration),
            "input_blob": _json_blob(self.repo, event.inputs),
            "kind": str(event.kind),
            "model": str(event.model),
            "output_blob": _json_blob(self.repo, event.outputs),
            "parent_ids": parents,
            "span_id": str(event.span_id),
            "time_unix": json_safe(event.timestamp),
            "trace_id": str(event.trace_id),
            "usage": _redact(json_safe(event.usage)),
        }
        event_id = self.repo.put("event", payload)
        updated = dict(run)
        updated["events"] = [*(run.get("events") or []), event_id]
        roots = list(run.get("roots") or [])
        updated["roots"] = roots if parents else [*roots, event_id]
        old_tips = [tip for tip in run.get("tips") or [] if tip not in parents]
        updated["tips"] = [*old_tips, event_id]
        next_run = self.repo.put("run", updated)
        self.repo.update_ref(self.ref, next_run, expected_old=self.run_id)
        self.run_id = next_run
        self.span_map[str(event.span_id)] = event_id
        return event_id

    def import_events(self, events: list[TraceEvent]) -> list[str]:
        by_span = {str(event.span_id): index for index, event in enumerate(events)}
        children: dict[int, list[int]] = defaultdict(list)
        degrees = [0] * len(events)
        for index, event in enumerate(events):
            dependencies = {str(value) for value in event.causal_span_ids}
            if event.parent_span_id:
                dependencies.add(str(event.parent_span_id))
            for dependency in dependencies:
                parent = by_span.get(dependency)
                if parent is not None and parent != index:
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
        order.extend(index for index, degree in enumerate(degrees) if degree)
        result = [""] * len(events)
        for index in order:
            result[index] = self.append(events[index], chain_if_parentless=False)
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
