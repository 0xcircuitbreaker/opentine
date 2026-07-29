"""MCP registration for v3 search/inspect/fork/evaluate/attest/promote."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from opentine.kernel import parse_oid
from opentine.repo import Repo
from opentine.repository._refs import normalize_ref

#: The only namespace an MCP client may move. A fork's ref update is an
#: unconditional overwrite (it compare-and-swaps against the value it just read),
#: so any writable ref here is a ref a model can destroy — and the content a model
#: reads from this repository is itself untrusted, which makes "fork onto
#: heads/main" a one-step prompt-injection payload. Mainline (``heads/``), release
#: gates (``promotions/``), labels (``tags/``) and remote-tracking refs stay
#: operator-only; ``experiments/`` is where forked work belongs.
_MCP_WRITABLE_REF_NAMESPACE = "experiments/"


def _writable_ref(ref: str) -> str:
    """Confine an MCP-supplied ref to the experiments namespace.

    The namespace test runs on the *canonical* name, not the caller's string, so
    the decision cannot disagree with the name that later reaches the filesystem.
    Testing the raw input also rejected the legitimate fully-qualified
    ``refs/experiments/…`` form, which normalization accepts.
    """
    normalized = normalize_ref(ref)
    if not normalized.startswith(_MCP_WRITABLE_REF_NAMESPACE):
        raise ValueError(f"MCP fork/resume may only write {_MCP_WRITABLE_REF_NAMESPACE}* refs")
    return normalized


def register_repository_tools(mcp, repo_path: str = ".", *, allow_promotion: bool = False) -> None:
    """Register the v3 repository tools on an MCP server.

    ``allow_promotion`` is off by default. A promotion ref is a release gate, and
    the run content an MCP client reads is untrusted, so text recorded inside a
    run can ask the model to promote a run of the attacker's choosing. The
    compare-and-swap stops an existing promotion being clobbered, but creating a
    new one is still an operator decision rather than a model's.
    """
    repo = Repo.open(repo_path)

    @mcp.tool()
    def search_runs(
        query: str = "",
        successful_only: bool = True,
        min_score: float | None = None,
        model: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search successful v3 runs and evaluation scores."""
        return [
            asdict(result)
            for result in repo.search(
                query,
                successful_only=successful_only,
                min_score=min_score,
                model=model,
                limit=limit,
            )
        ]

    @mcp.tool()
    def inspect_object(object_id: str, resolve_blobs: bool = True) -> dict[str, Any]:
        """Inspect a verified v3 object and optionally resolve its content blobs."""
        return repo.inspect(object_id, resolve_blobs=resolve_blobs)

    @mcp.tool()
    def context_slice(event_id: str, depth: int = 8) -> list[dict[str, Any]]:
        """Retrieve only the causal ancestors needed for an event."""
        return [asdict(entry) for entry in repo.context_slice(event_id, depth=depth)]

    @mcp.tool()
    def semantic_diff(run_a: str, run_b: str) -> dict[str, Any]:
        """Compare cost, latency, tool path, content, and event identity."""
        return asdict(repo.diff(run_a, run_b))

    @mcp.tool()
    def fork_run_v3(
        run_id: str,
        from_event: str,
        ref: str,
        model: str | None = None,
        prompt: str | None = None,
        policy: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        """Fork from the last good event with optional model, prompt, and policy overrides."""
        forked = repo.fork(
            run_id,
            from_event,
            overrides={"model": model, "policy": policy, "prompt": prompt},
            ref=_writable_ref(ref),
        )
        return {"ref": ref, "run_id": forked}

    @mcp.tool()
    def resume_run_v3(run_id: str, ref: str) -> dict[str, str]:
        """Resume at a run's last verified tip by creating a running fork."""
        if parse_oid(run_id)[0] != "run":
            raise ValueError("resume requires a run id")
        payload = repo.get(run_id).payload()
        tips = payload.get("tips") or []
        if not tips:
            raise ValueError("cannot resume a run without an event tip")
        resumed = repo.fork(run_id, tips[-1], overrides={"resume": True}, ref=_writable_ref(ref))
        return {"ref": ref, "run_id": resumed}

    @mcp.tool()
    def evaluate_run(
        run_id: str,
        scores: dict[str, float],
        evaluator: str,
    ) -> dict[str, str]:
        """Attach immutable evaluation scores to a run."""
        attestation = repo.attest(
            run_id,
            {"kind": "evaluation", "scores": scores},
            signer=evaluator,
        )
        return {"attestation_id": attestation}

    @mcp.tool()
    def attest_run(
        run_id: str,
        claim: dict[str, Any],
        signer: str,
    ) -> dict[str, str]:
        """Attach an approval or provenance claim to a run."""
        return {"attestation_id": repo.attest(run_id, claim, signer=signer)}

    if allow_promotion:

        @mcp.tool()
        def promote_run(
            run_id: str,
            name: str,
            expected_old: str | None = None,
        ) -> dict[str, str]:
            """CAS-update a promotion ref after evaluation or approval."""
            repo.promote(run_id, name, expected_old=expected_old)
            return {"ref": f"promotions/{name}", "run_id": run_id}

    @mcp.resource("tine-object://{object_id}")
    def object_resource(object_id: str) -> dict[str, Any]:
        return repo.inspect(object_id, resolve_blobs=True)
