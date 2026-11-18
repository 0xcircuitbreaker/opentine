"""The review runner: ``tine review run --fleet`` on every push (0.55).

One runner, packaged once (``deploy/review-runner``), runs hosted or
self-hosted. A mirror sync or a forge webhook hands it a push (``ref``,
``before``, ``after``, ``at``, optionally the pushed ``run``); it then

1. reviews the change with the reviewer fleet (:mod:`opentine._review_fleet`),
   every finding an existing ``opentine.review-finding`` whose time is the
   push time, so a deterministic fleet signs the same bytes in either mode;
2. runs ``.tine/evals.toml`` (:mod:`opentine._eval_ci`), existing
   ``tine-eval-verdict/1`` verdicts;
3. signs the existing admission VSA (``verification_summary/v1``) over the
   pushed run, ``PASSED`` only when no critical finding is open and every eval
   passed.

All three are signed by the runner's own key, a published, rotatable service
identity labelled ``review runner`` (:func:`identity`). It is a third-party
opinion and **never trusted by default**: a finding counts only when the
Review lists the key as a reviewer, and a gate only when the user's gate
policy names it (:func:`gate_policy` with no trusted runner trusts nothing).

Model credentials are the user's own: ``.tine/runner.toml`` names the
environment variables holding them, which reach the reviewers and never the
report. The model endpoints listed there are the only egress the sandbox
allows (:mod:`opentine._runner_sandbox`); the policy's digest is recorded in
every step's evidence. The report carries the push's cost.
"""

from __future__ import annotations

import base64
import os
import re
import tomllib
from pathlib import Path
from typing import Any

from opentine import _runner_sandbox as sandbox

CONFIG = Path(".tine") / "runner.toml"
MODES = ("hosted", "self-hosted")
TRIGGERS = ("mirror-sync", "webhook")
_ENV = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")
_WHEN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_RUN = re.compile(r"run:sha256:([0-9a-f]{64})")
_REV = re.compile(r"[0-9a-f]{7,64}")


def load_config(path: Path) -> dict[str, Any]:
    """``{"models": [{name, endpoint, credential_env}], "evals": path | None}``."""
    data = tomllib.loads(path.read_text("utf-8")) if path.is_file() else {}
    if set(data) - {"model", "runner"}:
        raise ValueError("runner.toml holds only [runner] and [[model]] tables")
    models = []
    for row in data.get("model", []):
        if not isinstance(row, dict) or set(row) - {"name", "endpoint", "credential_env"}:
            raise ValueError(
                "a [[model]] has name, endpoint and credential_env only "
                "(credentials stay in the environment, never in the file)"
            )
        env = row.get("credential_env")
        if env is not None and not (isinstance(env, str) and _ENV.fullmatch(env)):
            raise ValueError(f"credential_env must name an environment variable: {env!r}")
        sandbox.endpoint(str(row.get("endpoint", "")))
        models.append({"name": str(row.get("name", "")), "endpoint": row["endpoint"],
                       "credential_env": env})  # fmt: skip
    runner = data.get("runner", {})
    if not isinstance(runner, dict) or set(runner) - {"evals"}:
        raise ValueError("[runner] takes only evals")
    return {"models": models, "evals": runner.get("evals")}


def check_trigger(event: Any) -> dict[str, Any]:
    """A push from a mirror sync or a forge webhook, checked."""
    if not isinstance(event, dict) or event.get("source") not in TRIGGERS:
        raise ValueError(f"a trigger is a push whose source is one of {', '.join(TRIGGERS)}")
    if not (isinstance(event.get("at"), str) and _WHEN.fullmatch(event["at"])):
        raise ValueError("the trigger's at must be an RFC 3339 UTC time")
    if not isinstance(event.get("ref"), str) or not event["ref"]:
        raise ValueError("the trigger names the pushed ref")
    for name in ("before", "after"):
        value = event.get(name)
        if value is not None and not (isinstance(value, str) and _REV.fullmatch(value)):
            raise ValueError(f"the trigger's {name} must be a commit id")
    run = event.get("run")
    if run is not None and not (isinstance(run, str) and _RUN.fullmatch(run)):
        raise ValueError("the trigger's run must be a run:sha256: oid")
    return event


def identity(key: Any, previous: list[bytes] = ()) -> dict[str, Any]:  # type: ignore[assignment]
    """The runner's published service identity; *previous* keys it was rotated from."""
    from opentine._signing_pins import key_fingerprint

    raw = key.public_key().public_bytes_raw()
    return {"label": sandbox.LABEL, "algorithm": "ed25519", "public_key": raw.hex(),
            "public_key_b64url": base64.urlsafe_b64encode(raw).decode().rstrip("="),
            "fingerprint": key_fingerprint(raw), "trusted_by_default": False,
            "rotated_from": [key_fingerprint(old) for old in previous]}  # fmt: skip


def gate_policy(trusted: list[bytes], *, evals: int = 1, levels: tuple[str, ...] = ()) -> dict:
    """A merge gate policy trusting exactly the runner keys in *trusted* (maybe none)."""
    from opentine._merge_gates import FORMAT
    from opentine._signing_pins import key_fingerprint

    vsa = None
    if trusted:
        key = base64.urlsafe_b64encode(trusted[0]).decode().rstrip("=")
        vsa = {"key": key, "levels": list(levels), "policy": "", "resource": ""}
    signers = [key_fingerprint(raw) for raw in trusted]  # empty: no verdict counts
    return {"format": FORMAT, "vsa": vsa, "evals": {"min": evals, "signers": signers},
            "approvals": None}  # fmt: skip


def _vsa(key: Any, event: dict[str, Any], subject: str, passed: bool, policy: str) -> dict:
    from opentine.intoto import sign_statement
    from opentine.remote._vsa import build_vsa

    levels = ["OPENTINE_REVIEWED"] + (["OPENTINE_EVALS_PASSED"] if passed else [])
    statement = build_vsa("runner", event["ref"], subject, levels,
                          verifier="opentine:review-runner",
                          policy={"uri": "opentine:review-runner/sandbox", "digest": policy},
                          time_verified=event["at"])  # fmt: skip
    statement["predicate"]["verificationResult"] = "PASSED" if passed else "FAILED"
    return sign_statement(statement, key)


def run_push(repo: Any, review_id: str, fleet: Any, key: Any, event: dict[str, Any], *,
             config: dict[str, Any], mode: str, out: Path,
             key_id: str | None = None) -> dict[str, Any]:  # fmt: skip
    """Review, evaluate and attest one push; the report every step's evidence."""
    import hashlib

    from opentine import _review_run
    from opentine._eval_ci import run_ci
    from opentine._review_fleet import run_fleet

    if mode not in MODES:
        raise ValueError(f"mode is one of {', '.join(MODES)}")
    event = check_trigger(event)
    models = config["models"]
    names = [m["credential_env"] for m in models if m["credential_env"]]
    document = sandbox.policy([m["endpoint"] for m in models], names)
    digest = sandbox.digest(document)
    credentials = {name: os.environ[name] for name in names if name in os.environ}
    root = Path(repo.worktree)
    with sandbox.EgressGuard(document):
        text = _review_run.context(root, event.get("before"), None)
        review = run_fleet(repo, review_id, fleet, key, key_id, text,
                           extra_env=credentials, created_at=event["at"])  # fmt: skip
        evals = None
        if config["evals"]:
            evals = run_ci(root / config["evals"], key, out / "evals", repo_path=root,
                           created_at=event["at"])  # fmt: skip
    signed = review.pop("signed")
    critical = any(r["severity"] == "critical" for r in signed)
    passed = not critical and (evals is None or evals["ok"])
    subject = event.get("run") or "diff:sha256:" + hashlib.sha256(text.encode()).hexdigest()
    vsa = _vsa(key, event, subject, passed, digest)
    out.mkdir(parents=True, exist_ok=True)
    result = "PASSED" if passed else "FAILED"
    found = {"findings": [r["finding_id"] for r in signed]}
    steps = [{"step": "review", "evidence": {"sandbox_policy": digest, **found}},
             {"step": "evals", "evidence": {"sandbox_policy": digest,
                                            "ok": None if evals is None else evals["ok"]}},
             {"step": "attest", "evidence": {"sandbox_policy": digest, "subject": subject,
                                             "result": result}}]  # fmt: skip
    return {"mode": mode, "trigger": event, "identity": identity(key), "sandbox": document,
            "sandbox_policy": digest, "review": review, "evals": evals, "vsa": vsa,
            "credentials": {n: n in credentials for n in names}, "cost": review["cost"],
            "steps": steps}  # fmt: skip


__all__ = ["CONFIG", "MODES", "TRIGGERS", "check_trigger", "gate_policy", "identity",
           "load_config", "run_push"]  # fmt: skip
