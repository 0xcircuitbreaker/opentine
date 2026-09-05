"""The two composite *writer* ops: SPEC 1.4 and SPEC 4.5, in the order they happen.

``redact.blob`` and ``redact.value`` answer over an input someone has already
decided to redact, and ``sig.message`` answers over a document someone has
already decided to store. Neither asks an implementation to show what its
*writer* does, so the two rules that are entirely about ordering had no vector:

* **SPEC 1.4** -- "redaction happens before hashing". A writer that derives the
  oid first and scrubs afterwards names bytes no reader will ever see, and
  passes every ``redact.*`` vector.
* **SPEC 4.5** -- "the body is the payload as stored, after Repo.put's
  redaction". A writer that signs the caller's dict signs bytes no reader ever
  sees, and every attestation carrying a credential-shaped field verifies as
  ``mismatch``.

Both ops are answered by the real write path against a repository in a temporary
directory, for the same reason ``op_pack_install`` is: re-deriving the rule here
would test a second implementation written by the same author.
"""

from __future__ import annotations

import base64
import tempfile
from pathlib import Path
from typing import Any

from opentine._attest_view import SIGNATURE_KEY
from opentine.kernel import ObjectEnvelope
from tests.conformance.adapter_repo import _stored
from tests.conformance.keys import KEYS


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _repo(scratch: str, args: dict[str, Any]):
    from opentine.repository.store import Repo

    repo = Repo.init(Path(scratch) / "work")
    for raw in _stored(args).values():
        path = repo._object_path(ObjectEnvelope.decode(raw).oid)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return repo


def op_object_put(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 1.4 then SPEC 1.3: the body a reader gets, and the oid that names it."""
    object_type = args["type"]
    with tempfile.TemporaryDirectory() as scratch:
        repo = _repo(scratch, args)
        payload = inp.bytes_() if object_type == "blob" else inp.value
        oid = repo.put(object_type, payload, int(args.get("schema", 1)))
        return {"oid": oid, "body_b64": _b64(repo.get(oid).body)}


def op_attest_sign(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.5: sign the payload as stored, and store what was signed."""
    from opentine.repository._attest import attest

    value = inp.value
    with tempfile.TemporaryDirectory() as scratch:
        repo = _repo(scratch, args)
        oid = attest(
            repo,
            value["target_id"],
            value["claim"],
            signer=value["signer"],
            evidence_ids=value.get("evidence_ids"),
            key=KEYS[args["key"]] if args.get("key") else None,
            algorithm=args.get("algorithm", "hmac-sha256"),
            key_id=args.get("key_id"),
            signed_at=args.get("signed_at"),
        )
        envelope = repo.get(oid)
        return {
            "oid": oid,
            "body_b64": _b64(envelope.body),
            "signature": envelope.payload()[SIGNATURE_KEY],
        }


OPS = {"object.put": op_object_put, "attest.sign": op_attest_sign}
