"""Operator-authored claim and score arguments, parsed before anything is written.

Split out of ``_repo_cli_write`` when the write verbs gained signing, and kept
together because both functions here enforce the same idea: an attestation is
immutable and content-addressed, so a malformed claim must be refused at the
door rather than stored and raised on by every later reader.

``_claim`` refuses a JSON value that is not an *object* because
``repository/_associations.evaluations`` and ``repository/search.py`` both read a
claim as a mapping. ``_scores`` refuses a non-finite or repeated score because
``repo-search`` averages scores, and a ``nan`` poisons every average it reaches.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

#: A claim is operator-authored, but it is still read off disk or off a shell
#: argument, and it is stored verbatim inside a content-addressed object.
MAX_CLAIM_BYTES = 1 << 20


def parse_claim(args: argparse.Namespace) -> dict[str, Any]:
    """Parse ``--claim`` / ``--claim-file`` into a JSON object, or refuse."""
    source = "--claim"
    if getattr(args, "claim_file", None):
        source = "--claim-file"
        text = Path(args.claim_file).read_text(encoding="utf-8")
    else:
        text = args.claim or ""
    if len(text.encode("utf-8", "replace")) > MAX_CLAIM_BYTES:
        raise ValueError(f"{source} exceeds the {MAX_CLAIM_BYTES}-byte claim limit")
    try:
        parsed = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"{source} must be valid JSON: {exc}") from None
    if not isinstance(parsed, dict):
        # An attestation claim is read back as a mapping by _associations and by
        # search; a bare list, number, or string would store fine and then raise
        # on every reader, so it is refused at the door instead.
        raise ValueError(f"{source} must be a JSON object, got {type(parsed).__name__}")
    return parsed


def parse_scores(pairs: list[str] | None) -> dict[str, float]:
    """Parse repeated ``--score NAME=VALUE`` into the evaluation claim's mapping."""
    scores: dict[str, float] = {}
    for pair in pairs or []:
        name, separator, raw = pair.partition("=")
        if not separator or not name:
            raise ValueError(f"--score must be NAME=VALUE, got {pair!r}")
        try:
            value = float(raw)
        except ValueError:
            raise ValueError(f"--score {name} must be a number, got {raw!r}") from None
        if not math.isfinite(value):
            # search averages scores; a nan or inf would poison every average it
            # reaches, and _finite drops it silently on the way back out.
            raise ValueError(f"--score {name} must be finite, got {raw!r}")
        if name in scores:
            raise ValueError(f"--score {name} was given twice")
        scores[name] = value
    if not scores:
        raise ValueError("evaluate requires at least one --score NAME=VALUE")
    return scores


__all__ = ["MAX_CLAIM_BYTES", "parse_claim", "parse_scores"]
