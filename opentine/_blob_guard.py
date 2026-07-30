"""Both halves of the compatibility JSON blob contract, kept in one module.

The writer and the reader are paired here on purpose. Every asymmetry this
release has produced came from a rule enforced on one side and assumed on the
other; when the two functions sit side by side a new rule cannot be added to
one half without the other half being visibly wrong.
"""

from __future__ import annotations

import json
from typing import Any

from opentine._artifact_io import compact_token_budget
from opentine._jsonsafe import json_safe
from opentine._v3_guards import guarded_redaction
from opentine.kernel import KernelError, _parse_int, canonical_json, validate_json_shape


def guarded_blob_body(value: Any) -> bytes:
    """Canonicalize a JSON blob, refusing anything ``guarded_blob_parse`` cannot read.

    The reader enforces four rules on every blob: the body parses as JSON, its
    structure fits the shared depth/token budget, the value is an *object*, and
    the bytes are its canonical encoding. The first and last hold by
    construction only because the reader re-parses with the kernel's own
    ``parse_int`` hook: ``canonical_json`` renders any finite float with
    ``2**53 <= |v| < 1e21`` as a bare *integer* literal, so a hookless re-parse
    yields an int whose re-encoding raises and turns a written blob into an
    unreadable one. That hook is what makes canonicity a genuine fixpoint, and
    it lives in ``guarded_blob_parse`` below -- not in an assumption here. The
    write side therefore enforces the remaining two rules explicitly. Failing at
    save leaves the run in memory, where the caller can still shrink or wrap the
    offending value; failing at load destroys the run the blob was written to
    preserve.

    The third rule the reader cannot restate is Unicode: ``json_safe`` happily
    carries a str holding an unpaired UTF-16 surrogate, which has no UTF-8
    spelling at all, and the encode inside redaction then raised a bare
    ``UnicodeEncodeError`` naming a position in a fragment nobody could locate.
    ``guarded_redaction`` names the field path instead, for every blob this
    writes: step inputs and outputs, the run manifest, transcript, cache and
    policies.
    """
    safe = json_safe(value)
    if not isinstance(safe, dict):
        raise ValueError(
            "step and run JSON must be an object to survive a later load; got "
            f"{type(value).__name__}; wrap the value in a mapping "
            'such as {"value": ...}'
        )
    body = canonical_json(guarded_redaction(safe, where="step or run JSON"))
    try:
        validate_json_shape(body, max_tokens=compact_token_budget(len(body)))
    except KernelError as exc:
        raise ValueError(
            "step or run JSON exceeds the structural limit the loader enforces; "
            "shrink or summarize the offending input/output before saving"
        ) from exc
    return body


def guarded_blob_parse(body: bytes) -> dict[str, Any]:
    """Read a blob body under exactly the rules ``guarded_blob_body`` wrote it under.

    ``parse_int`` is the kernel's own hook, not the default ``int``: it is the
    single reason ``canonical_json`` output re-encodes to itself, because it
    demotes an out-of-range integer literal back to the float that produced it.
    Every other body reader in the kernel already passes it
    (``ObjectEnvelope.payload`` and ``ObjectEnvelope.decode``); a bare
    ``json.loads`` here made this the one reader that could not read what the
    writer above had just accepted.

    The canonical re-encode is inside the ``try`` so that a body this reader
    cannot re-encode at all -- a digit run that overflows to infinity, a
    ``NaN``/``Infinity`` literal -- surfaces as this reader's own typed refusal
    instead of leaking a ``KernelError`` from the kernel encoder.
    """
    try:
        # The exact budget guarded_blob_body applied at write, on the same bytes.
        validate_json_shape(body, max_tokens=compact_token_budget(len(body)))
        parsed = json.loads(body, parse_int=_parse_int)
        canonical = canonical_json(parsed)
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise ValueError("compatibility JSON blob is malformed") from exc
    if not isinstance(parsed, dict) or canonical != body:
        raise ValueError("compatibility JSON blob must be a canonical object")
    return parsed
