"""Per-run sandbox policies (0.69): the ``opentine.sandbox-policy/1`` claim convention.

A runner (or the hook that starts an agent) describes the sandbox a run was
given and signs it onto the run as an attestation (an existing object kind)::

    {"convention": "opentine.sandbox-policy/1", "policy": POLICY,
     "policy_digest": "sha256:...", "recorded_at": "YYYY-MM-DDTHH:MM:SSZ"}

``POLICY`` is canonicalised before it is digested: ``network_allowlist`` (host
names, lower case, sorted, unique), ``mounts`` (``{"path", "mode": ro|rw}``
sorted by path), ``privileges`` (sorted, unique), ``image_digest`` (the
container image, ``sha256:``) and ``seccomp_digest`` (the seccomp profile,
``sha256:`` or ``null``). ``policy_digest`` is ``sha256:`` of its canonical
JSON, so two runners that describe the same sandbox give the same digest. The
record is held (``containment:policy:RUN``) and never released.

``tine containment check RUN`` compares the recorded digest with the declared
one (a policy file or a pinned digest). A different digest, or no signed policy
when one is declared, is the command-level failure ``sandbox-policy-mismatch``
(owner decision D12: one of the two hard containment findings; it is not a
``tine verify`` code). Two recorded policies with different digests on one run
are a mismatch too, and the gate's allowlist is the intersection of them, so a
loop that signs a wider policy later cannot widen its own sandbox evidence. A
policy signed by a key outside the owner-pinned
``runner`` role is reported ``advisory:containment.runner-unpinned``.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

from opentine import _containment_records as records
from opentine.kernel import canonical_json

CONVENTION = "opentine.sandbox-policy/1"
HOLD = "containment:policy:"
MISMATCH = "sandbox-policy-mismatch"
_FIELDS = ("network_allowlist", "mounts", "privileges", "image_digest", "seccomp_digest")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_HOST = re.compile(r"(\*\.)?[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
MAX_ITEMS = 1024


def _strings(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError(f"{name} is a list of at most {MAX_ITEMS} strings")
    if not all(isinstance(v, str) and v for v in value):
        raise ValueError(f"{name} holds non-empty strings")
    return sorted(set(value))


def canonical(policy: Any) -> dict[str, Any]:
    """The canonical form of a sandbox policy (raises ``ValueError``)."""
    if not isinstance(policy, dict) or set(policy) != set(_FIELDS):
        raise ValueError(f"a sandbox policy has exactly the fields {', '.join(_FIELDS)}")
    hosts = [h.lower() for h in _strings(policy["network_allowlist"], "network_allowlist")]
    if not all(_HOST.fullmatch(h) for h in hosts):
        raise ValueError("network_allowlist names hosts (example.org or *.example.org)")
    mounts = policy["mounts"]
    if not isinstance(mounts, list) or len(mounts) > MAX_ITEMS:
        raise ValueError(f"mounts is a list of at most {MAX_ITEMS} entries")
    seen: dict[str, dict[str, str]] = {}
    for m in mounts:
        shaped = isinstance(m, dict) and set(m) == {"path", "mode"}
        if (
            not shaped
            or not isinstance(m["path"], str)
            or not m["path"]
            or m["mode"]
            not in (
                "ro",
                "rw",
            )
        ):
            raise ValueError("a mount is {path, mode: ro|rw}")
        seen[m["path"]] = {"path": m["path"], "mode": m["mode"]}
    image, seccomp = policy["image_digest"], policy["seccomp_digest"]
    if not isinstance(image, str) or not _DIGEST.fullmatch(image):
        raise ValueError("image_digest is sha256:<64 hex>")
    if seccomp is not None and (not isinstance(seccomp, str) or not _DIGEST.fullmatch(seccomp)):
        raise ValueError("seccomp_digest is sha256:<64 hex> or null")
    return {"network_allowlist": sorted(set(hosts)), "mounts": [seen[p] for p in sorted(seen)],
            "privileges": _strings(policy["privileges"], "privileges"),
            "image_digest": image, "seccomp_digest": seccomp}  # fmt: skip


def digest(policy: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(canonical(policy))).hexdigest()


def record(repo: Any, run: str, policy: Any, key: Any, *, now: float | None = None) -> str:
    """Sign and hold the sandbox policy of *run*; the attestation id."""
    body = canonical(policy)
    claim = {"convention": CONVENTION, "policy": body, "policy_digest": digest(body),
             "recorded_at": records.rfc3339(time.time() if now is None else now)}  # fmt: skip
    return records.record(repo, run, claim, key, HOLD + run)


def recorded(repo: Any, run: str) -> list[dict[str, Any]]:
    """The held policy records of *run*, each with ``problems`` (empty when valid)."""
    out = []
    for target, row in records.held(repo, HOLD + run):
        if target != HOLD + run:  # another run whose id starts with this one
            continue
        claim, problems = row["claim"] or {}, []
        if claim.get("convention") != CONVENTION:
            problems.append("not an opentine.sandbox-policy/1 claim")
        else:
            try:
                if digest(claim.get("policy")) != claim.get("policy_digest"):
                    problems.append("policy_digest is not the digest of the recorded policy")
            except ValueError as exc:
                problems.append(str(exc))
        if not row["signed"]:
            problems.append("the record is not signed by the key its signer field names")
        if row["target"] != run:
            problems.append("the record is attached to another run")
        out.append({**row, "problems": problems})
    return out


def allowlist(repo: Any, run: str) -> list[str] | None:
    """Hosts every valid recorded policy of *run* allows (a later record cannot widen it)."""
    lists = [set(r["claim"]["policy"]["network_allowlist"])
             for r in recorded(repo, run) if not r["problems"]]  # fmt: skip
    return sorted(set.intersection(*lists)) if lists else None


def check(repo: Any, run: str, declared: str | None) -> dict[str, Any]:
    """``{"ok", "run", "declared", "policies", "findings"}`` for ``tine containment check``."""
    rows, findings = recorded(repo, run), []
    for row in rows:
        state = records.role_state(repo, row["signer"], "runner")
        row["verification"] = state
        for problem in row["problems"]:
            findings.append({"code": f"fail:{MISMATCH}", "record": row["oid"], "message": problem})
        if state != "verified" and not row["problems"]:
            findings.append({"code": "advisory:containment.runner-unpinned", "record": row["oid"],
                             "message": state})  # fmt: skip
    valid = [r for r in rows if not r["problems"]]
    if declared is not None and not valid:
        findings.append({"code": f"fail:{MISMATCH}", "record": None,
                         "message": "no signed sandbox policy is recorded"})  # fmt: skip
    if len({r["claim"]["policy_digest"] for r in valid}) > 1:
        findings.append({"code": f"fail:{MISMATCH}", "record": None,
                         "message": "the run's recorded policies disagree"})  # fmt: skip
    for row in valid:
        got = row["claim"]["policy_digest"]
        if declared is not None and got != declared:
            findings.append({"code": f"fail:{MISMATCH}", "record": row["oid"],
                             "message": f"recorded {got}, declared {declared}"})  # fmt: skip
    policies = [
        {"record": r["oid"], "signer": r["signer"], "verification": r["verification"],
         "policy_digest": (r["claim"] or {}).get("policy_digest")}
        for r in rows
    ]  # fmt: skip
    ok = not any(f["code"].startswith("fail:") for f in findings)
    return {"ok": ok, "run": run, "declared": declared, "policies": policies,
            "findings": findings}  # fmt: skip


__all__ = ["CONVENTION", "HOLD", "MISMATCH", "allowlist", "canonical", "check", "digest",
           "record", "recorded"]  # fmt: skip
