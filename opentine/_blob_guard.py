"""Write-side guard keeping compatibility JSON blobs within reader limits."""

from __future__ import annotations

from typing import Any

from opentine._artifact_io import compact_token_budget
from opentine._canon import _redact
from opentine._jsonsafe import json_safe
from opentine.kernel import KernelError, canonical_json, validate_json_shape
from opentine.redaction import redact_value


def guarded_blob_body(value: Any) -> bytes:
    """Canonicalize a JSON blob, refusing anything ``blob_json`` could never read.

    The reader enforces four rules on every blob: the body parses as JSON, its
    structure fits the shared depth/token budget, the value is an *object*, and
    the bytes are its canonical encoding. The first and last hold by
    construction (``json_safe`` stringifies keys and rejects collisions, and
    ``canonical_json`` output is a re-encoding fixpoint), so the write side must
    enforce the other two explicitly. Failing at save leaves the run in memory,
    where the caller can still shrink or wrap the offending value; failing at
    load destroys the run the blob was written to preserve.
    """
    safe = json_safe(value)
    if not isinstance(safe, dict):
        raise ValueError(
            "step and run JSON must be an object to survive a later load; got "
            f"{type(value).__name__}; wrap the value in a mapping "
            'such as {"value": ...}'
        )
    body = canonical_json(redact_value(_redact(safe)))
    try:
        validate_json_shape(body, max_tokens=compact_token_budget(len(body)))
    except KernelError as exc:
        raise ValueError(
            "step or run JSON exceeds the structural limit the loader enforces; "
            "shrink or summarize the offending input/output before saving"
        ) from exc
    return body
