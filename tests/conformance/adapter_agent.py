"""Reference ops for SPEC 4.8 (``tine-actions/1``), 4.9 (``opentine-agent/1``) and 4.11."""

from __future__ import annotations

import base64
from typing import Any

from opentine import _agent_identity as identity
from opentine._actions_manifest import chain
from opentine.kernel import canonical_json


def op_agent_ref(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.9: validate a record and derive its ``agt_`` ref; refuse a bad record."""
    record = identity.validate(inp.value)
    stable = {name: record[name] for name in identity.STABLE_FIELDS}
    hashed = identity.DOMAIN + canonical_json(stable)
    return {"ref": identity.agent_ref(record), "hashed_b64": base64.b64encode(hashed).decode()}


def op_actions_chain(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.8: the entry hash chain, seeded from the run id."""
    value = inp.value
    links = chain(value["run_id"], list(value["digests"]))
    return {"chain": links}


def op_fleet_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.11 (0.48 vectors): a signed ``opentine-fleet-record/1`` document."""
    from opentine import _fleet_record

    value = inp.value
    key = value.get("public_key")
    ok, detail = _fleet_record.verify(value["document"], bytes.fromhex(key) if key else None)
    if not ok:
        raise ValueError(detail)
    document = value["document"]
    return {**document["record"], "run_id": document["run_id"],
            "run_digest": document["run_digest"],
            "state": "verified" if key else "verified-tofu"}  # fmt: skip


OPS = {
    "agent.ref": op_agent_ref,
    "actions.chain": op_actions_chain,
    "fleet.verify": op_fleet_verify,
}
