"""``tine-actions/1``: a signed manifest of everything one run's agent did.

The body is recomputed from the run on every check, never read from a cache::

    {"scheme": "tine-actions/1", "run_id", "run_digest", "agent_ref",
     "identity", "entries": [{seq, step_id, tool, verbs, digest, chain}],
     "spawns": [step ids], "head"}

* ``digest`` is SHA-256 over the action's redacted record, and ``chain``
  links every entry to the one before it, starting from a value bound to the
  run id, so a dropped, reordered or edited action changes ``head``.
* ``run_id`` and ``run_digest`` (SHA-256 of the run's redacted step graph) bind
  the manifest to exactly one run: a manifest moved onto another run -- even one
  with identical actions -- no longer matches the body that run produces.
* ``identity`` is the run's ``opentine-agent/1`` record; when it names a
  ``key_fpr``, the signing key must be that key, or the verdict is ``mismatch``.

The signature is a ``sign_block``/``verify_block`` block (the same algorithms,
header and fail-closed verdicts as ``tine-attest/1``) under its own domain
prefix, so no other opentine signature can be lifted onto a manifest.
"""

from __future__ import annotations

import hashlib
from typing import Any

from opentine import _agent_identity as identity
from opentine._actions import extract_actions
from opentine._graph_serde import run_to_dict
from opentine._signing_verify import HEADER_KEYS, sign_block
from opentine.kernel import canonical_json

SCHEME = "tine-actions/1"
DOMAIN = b"opentine.actions.v1:"
SCHEMES = (SCHEME,)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_digest(run: Any) -> str:
    """SHA-256 of the run id and its redacted step graph (metadata excluded)."""
    graph = run_to_dict(run, redact=True)["graph"]
    return _sha(canonical_json({"graph": graph, "run_id": run.id}))


def seed(run_id: str) -> str:
    """The chain's starting value: the run id, so no chain fits another run."""
    return _sha(b"tine-actions/1\0" + run_id.encode("utf-8"))


def chain(run_id: str, digests: list[str]) -> list[str]:
    """The hash chain over entry *digests*, seeded from *run_id*."""
    link = seed(run_id)
    links = []
    for digest in digests:
        link = _sha(f"{link}:{digest}".encode())
        links.append(link)
    return links


def build_body(run: Any) -> dict[str, Any]:
    """The manifest body for *run* (raises on an unreadable run)."""
    actions, truncated = extract_actions(run)
    if truncated:
        raise ValueError("run has more actions than a manifest may cover")
    # Meters (cost, time) are not actions: zeroed so re-pricing never breaks a manifest.
    digests = [_sha(canonical_json({**a.to_dict(), "cost": 0, "ts": 0})) for a in actions]
    links = chain(run.id, digests)
    entries = []
    for action, digest, link in zip(actions, digests, links, strict=True):
        entries.append(
            {
                "chain": link,
                "digest": digest,
                "seq": action.seq,
                "step_id": action.step_id,
                "tool": action.tool,
                "verbs": list(action.verbs),
            }
        )
    spawns = [e["step_id"] for e in entries if "spawn_subagent" in e["verbs"]]
    record = identity.run_identity(run)
    return {
        "agent_ref": identity.run_agent_ref(run),
        "entries": entries,
        "head": links[-1] if links else seed(run.id),
        "identity": record,
        "run_digest": run_digest(run),
        "run_id": run.id,
        "scheme": SCHEME,
        "spawns": spawns,
    }


def signed_message(body: dict[str, Any], header: dict[str, Any]) -> bytes:
    view = {"body": body, "header": {key: header.get(key) for key in HEADER_KEYS}}
    return DOMAIN + canonical_json(view)


def sign(
    run: Any,
    key: Any,
    *,
    algorithm: str,
    key_id: str | None = None,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """A complete manifest for *run*: ``{"body": ..., "signature": block}``."""
    body = build_body(run)
    block = sign_block(
        lambda header: signed_message(body, header),
        key,
        algorithm=algorithm,
        scheme=SCHEME,
        key_id=key_id,
        signer=body["agent_ref"],
        signed_at=signed_at,
        subject="action manifest",
    )
    return {"body": body, "signature": block}


__all__ = [
    "DOMAIN",
    "SCHEME",
    "SCHEMES",
    "build_body",
    "chain",
    "seed",
    "run_digest",
    "sign",
    "signed_message",
]
