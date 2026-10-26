"""SPEC 4.8 ``tine-actions/1`` and SPEC 4.9 ``opentine-agent/1``."""

from __future__ import annotations

from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V

VERIFIER = "verifier"
SCHEME = "tine-actions/1"
D1, D2 = "11" * 32, "22" * 32
FPR = "sha256:" + "ab" * 32
REF = "agt_" + "0123456789abcdef" * 2

RECORD = {
    "scheme": "opentine-agent/1",
    "harness": "claude-code",
    "harness_version": "",
    "model": "claude-opus-5-5",
    "provider": "anthropic",
    "definition_digest": "sha256:" + "cd" * 32,
    "key_fpr": "",
    "instance": "",
    "parent": "",
    "parent_run": "",
    "spawn_step": "",
}

BODY = {
    "agent_ref": "agt_" + "5" * 32,
    "entries": [
        {
            "chain": "33" * 32,
            "digest": D1,
            "seq": 0,
            "step_id": "step-1",
            "tool": "Bash",
            "verbs": ["exec"],
        }
    ],
    "head": "33" * 32,
    "identity": None,
    "run_digest": "44" * 32,
    "run_id": "run-alpha",
    "scheme": SCHEME,
    "spawns": [],
}
HEADER = {
    "alg": "hmac-sha256",
    "key_id": "agent-key",
    "scheme": SCHEME,
    "signed_at": "2026-10-26T00:00:00Z",
    "signer": "agt_" + "5" * 32,
}


def _message(name: str, intent: str, body: dict, header: dict = HEADER, **extra) -> Case:
    return Case(
        id=f"actions.{name}",
        section="4.8",
        checklist=(8,),
        op="sig.message",
        profile=VERIFIER,
        expect=ACCEPT,
        intent=intent,
        input=V({"document": body, "header": header}),
        args={"scheme": SCHEME, "key": "hmac_a"},
        **extra,
    )


def _chain(name: str, intent: str, run_id: str, digests: list, **extra) -> Case:
    return Case(
        id=f"actions.chain.{name}",
        section="4.8",
        checklist=(8,),
        op="actions.chain",
        profile=VERIFIER,
        expect=ACCEPT,
        intent=intent,
        input=V({"digests": digests, "run_id": run_id}),
        **extra,
    )


def _agent(name: str, expect: str, intent: str, record: dict, **extra) -> Case:
    return Case(
        id=f"agent.{name}",
        section="4.9",
        checklist=(8,),
        op="agent.ref",
        profile=VERIFIER,
        expect=expect,
        intent=intent,
        input=V(record),
        **extra,
    )


ACTIONS = Family(
    "48-actions.json",
    "4.8",
    "actions",
    (
        _message(
            "worked-vector",
            "the signed message is opentine.actions.v1: + v3 canonical JSON of body and header",
            BODY,
        ),
        _message(
            "run-id-moved",
            "the run id is inside the signed body, so a manifest cannot be moved to another run",
            {**BODY, "run_id": "run-beta"},
            twin="actions.worked-vector",
            must_differ=True,
        ),
        _message(
            "signer-changed",
            "the header signer (the agent ref) is covered",
            BODY,
            {**HEADER, "signer": "agt_" + "6" * 32},
            twin="actions.worked-vector",
            must_differ=True,
        ),
        _chain(
            "worked-vector",
            "each link is sha256(previous:digest), seeded by the run",
            "run-alpha",
            [D1, D2],
        ),
        _chain(
            "other-run",
            "the same digests under another run id give a different chain",
            "run-beta",
            [D1, D2],
            twin="actions.chain.worked-vector",
            must_differ=True,
        ),
        _chain(
            "truncated",
            "dropping the last entry leaves a chain whose head differs",
            "run-alpha",
            [D1],
            twin="actions.chain.worked-vector",
            must_differ=True,
        ),
    ),
)

AGENT = Family(
    "49-agent.json",
    "4.9",
    "agent",
    (
        _agent("worked-vector", ACCEPT, "the ref hashes harness, definition, model, key", RECORD),
        _agent(
            "instance-and-lineage-excluded",
            ACCEPT,
            "instance, parent and spawn fields do not change the ref",
            {**RECORD, "instance": "ef" * 16, "parent": REF, "parent_run": "run-p"},
            twin="agent.worked-vector",
            must_differ=False,
        ),
        _agent(
            "key-bound",
            ACCEPT,
            "binding a signing key fingerprint gives a different agent",
            {**RECORD, "key_fpr": FPR},
            twin="agent.worked-vector",
            must_differ=True,
        ),
        _agent(
            "cyrillic-lookalike",
            ACCEPT,
            "a look-alike harness name (Cyrillic a) is a different agent, never the same ref",
            {**RECORD, "harness": "clаude-code"},
            twin="agent.worked-vector",
            must_differ=True,
        ),
        _agent(
            "fullwidth-harness",
            REJECT,
            "a name NFKC would change is refused, not normalised in place",
            {**RECORD, "harness": "ｃlaude-code"},
            reason="agent.not-normalised",
        ),
        _agent(
            "parent-prefix",
            REJECT,
            "a parent ref shorter than agt_ + 32 hex is refused",
            {**RECORD, "parent": REF[:12]},
            reason="agent.field-malformed",
        ),
        _agent(
            "upper-case-fingerprint",
            REJECT,
            "a fingerprint is lower-case hex in full",
            {**RECORD, "key_fpr": FPR.upper()},
            reason="agent.field-malformed",
        ),
        _agent(
            "unknown-field",
            REJECT,
            "a record with an undefined key is refused",
            {**RECORD, "role": "admin"},
            reason="agent.unknown-field",
        ),
        _agent(
            "no-harness",
            REJECT,
            "a record must name a harness",
            {**RECORD, "harness": ""},
            reason="agent.harness-missing",
        ),
    ),
)

FAMILIES = (ACTIONS, AGENT)
