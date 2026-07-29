"""Write-side guard keeping compatibility JSON blobs within reader limits."""

from __future__ import annotations

from typing import Any

from opentine._canon import _redact
from opentine._jsonsafe import json_safe
from opentine.kernel import KernelError, canonical_json, validate_json_shape
from opentine.redaction import redact_value

#: Structural-token bound ``blob_json`` enforces on every read. Writers must hold
#: the same line, or a wide-but-legal step input/output saved cleanly and then
#: failed every later ``load_run`` — with fsck still reporting the repo healthy.
MAX_BLOB_STRUCTURAL_TOKENS = 200_000


def guarded_blob_body(value: Any) -> bytes:
    """Canonicalize a JSON blob, refusing structure the loader could never read.

    Failing at save leaves the run in memory, where the caller can still shrink
    the offending value; failing at load destroys the run the blob was written
    to preserve.
    """
    body = canonical_json(redact_value(_redact(json_safe(value))))
    try:
        validate_json_shape(body, max_tokens=MAX_BLOB_STRUCTURAL_TOKENS)
    except KernelError as exc:
        raise ValueError(
            "step or run JSON exceeds the structural limit the loader enforces; "
            "shrink or summarize the offending input/output before saving"
        ) from exc
    return body
