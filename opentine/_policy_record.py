"""Policy admission records (0.74): the ``opentine.policy-admission/1`` claim convention.

``tine policy check`` signs its decision as an **attestation** (an existing
object kind) on the subject run, in the shape of a verification summary::

    {"convention": "opentine.policy-admission/1",
     "verificationResult": "PASSED" | "FAILED",   # allow | deny
     "decision": "allow" | "deny",
     "policy": {"name": NAME, "digest": "sha256:.."},
     "subject": RUN, "input_digest": "sha256:..",
     "rules": [{"id", "effect", "outcome", "code"}],
     "at": TIME}

It is held under ``policy-admission:RUN-HEX`` and never released, so a loop
cannot delete a deny. The signer is the key that signed (``signer`` is checked
against the signature's key); a pinned ``optimizer`` key is refused. Whether a
record counts for a consumer is a role question: :func:`rows` reports the
signer's roles from the owner-pinned key roles only (a ``policy`` role is the
expected one). No object kind and no ``tine verify`` code is added
(docs/POLICY.md).
"""

from __future__ import annotations

import re
from typing import Any

CONVENTION = "opentine.policy-admission/1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_FIELDS = {"convention", "verificationResult", "decision", "policy", "subject",
           "input_digest", "rules", "at"}  # fmt: skip


def claim(policy: dict[str, Any], digest: str, run: str, input_digest: str,
          result: dict[str, Any], at: str) -> dict[str, Any]:  # fmt: skip
    return {"convention": CONVENTION,
            "verificationResult": "PASSED" if result["decision"] == "allow" else "FAILED",
            "decision": result["decision"],
            "policy": {"name": policy["name"], "digest": digest},
            "subject": run, "input_digest": input_digest,
            "rules": [{k: r[k] for k in ("id", "effect", "outcome", "code")}
                      for r in result["rules"]], "at": at}  # fmt: skip


def check_claim(value: Any) -> list[str]:
    """Problems with *value* as an admission claim (none: valid)."""
    if not isinstance(value, dict) or value.get("convention") != CONVENTION:
        return [f"not an {CONVENTION} claim"]
    if set(value) != _FIELDS:
        return [f"an admission claim has exactly {', '.join(sorted(_FIELDS))}"]
    if value["decision"] not in ("allow", "deny"):
        return ["decision is allow or deny"]
    if value["verificationResult"] != ("PASSED" if value["decision"] == "allow" else "FAILED"):
        return ["verificationResult does not match the decision"]
    pol = value["policy"]
    if not isinstance(pol, dict) or not _DIGEST.fullmatch(str(pol.get("digest"))):
        return ["policy names a sha256: digest"]
    if not _DIGEST.fullmatch(str(value["input_digest"])):
        return ["input_digest is a sha256: digest"]
    rules = value["rules"]
    if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
        return ["rules is a list of rule results"]
    required = [r for r in rules if r.get("effect") == "require"]
    allow = all(r.get("outcome") == "true" for r in required)
    if allow != (value["decision"] == "allow"):
        return ["the decision does not follow from the require rules"]
    return []


def hold_target(run: str) -> str:
    from opentine.repository._holds import POLICY_ADMISSION

    return POLICY_ADMISSION + run.rsplit(":", 1)[-1]


def record(repo: Any, run: str, body: dict[str, Any], key: Any) -> str:
    """Sign *body* onto *run* and hold it; the attestation id."""
    from opentine._sabotage import scorers
    from opentine._signing_pins import key_fingerprint
    from opentine.repository._attest import attest
    from opentine.repository._holds import edit_holds, holds_path
    from opentine.repository._link_touch import touch_links

    problems = check_claim(body)
    if problems:
        raise ValueError(f"not a valid admission record: {problems[0]}")
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    if signer in scorers(repo)[1]:
        raise ValueError("policy.key-separation: a pinned optimizer key cannot sign admissions")
    oid = attest(repo, run, body, signer=signer, key=key, algorithm="ed25519",
                 signed_at=body["at"])  # fmt: skip
    touch_links(repo, [oid])
    row = {"oid": oid, "target": hold_target(run)}
    edit_holds(holds_path(repo), lambda held: [*(r for r in held if r != row), row])
    return oid


def rows(repo: Any, run: str) -> list[dict[str, Any]]:
    """``[{oid, signer, signed, roles, claim}]`` of the held admissions of *run*."""
    from pathlib import Path

    from opentine._policy_input import _roles
    from opentine._query_rows import _signed_attestation
    from opentine.repository._holds import holds_path, read_holds

    _status, by_key = _roles(Path(repo.path))
    out = []
    for row in read_holds(holds_path(repo)):
        if row["target"] != hold_target(run):
            continue
        try:
            payload = repo.get(row["oid"]).payload()
        except Exception:  # noqa: BLE001 - an unreadable record is reported unsigned
            payload = {}
        payload = payload if isinstance(payload, dict) else {}
        value = payload.get("claim")
        out.append({"oid": row["oid"], "signer": payload.get("signer"),
                    "signed": bool(payload) and _signed_attestation(payload)
                    and not check_claim(value),
                    "roles": by_key.get(payload.get("signer"), []),
                    "claim": value if isinstance(value, dict) else None})  # fmt: skip
    return out


__all__ = ["CONVENTION", "check_claim", "claim", "hold_target", "record", "rows"]
