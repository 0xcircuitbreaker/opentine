"""Judge provenance (0.65): the ``opentine.judge-provenance/1`` claim convention.

An ``llm-judge`` scorer describes itself in one canonical document::

    {"convention": "opentine.judge-provenance/1",
     "model": "<PROVIDER[:MODEL] the judge called>",
     "prompt_digest": "sha256:<hex of the prompt template, UTF-8>",
     "rubric_digest": "sha256:<hex of the rubric text>" | null,
     "sampling": {"temperature": "0", ...}}   # decimal strings, sorted keys

Its pin, ``jp1+sha256:<64 hex>`` over the canonical JSON, is the
``scorer_version`` of every ``tine-eval-verdict/1`` the judge scores, so it is
inside the signed verdict body. The eval folder keeps the document beside the
verdicts as ``judge.json``. ``tine eval verify`` recomputes the pin: an edited
rubric digest no longer matches the signed ``scorer_version``
(``eval.summary-mismatch``), and editing ``scorer_version`` to match breaks the
verdict signature (``eval-verdict.bad-signature``). No verdict field, object
kind or ``tine verify`` code is added (docs/AUDIT_GAMES.md).
"""

from __future__ import annotations

import hashlib
import re
from decimal import Decimal
from typing import Any

from opentine.kernel import canonical_json

CONVENTION = "opentine.judge-provenance/1"
FILE_NAME = "judge.json"
PREFIX = "jp1+sha256:"
FIELDS = ("convention", "model", "prompt_digest", "rubric_digest", "sampling")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PARAM = re.compile(r"[a-z_]{1,32}")
MAX_PARAMS = 16


def text_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _decimal(value: Any) -> str:
    number = Decimal(str(value))
    if not number.is_finite():
        raise ValueError(f"sampling value {value!r} is not a finite number")
    return format(number.normalize(), "f")


def build(model: str, prompt: str, *, rubric: str | None = None,
          sampling: dict[str, Any] | None = None) -> dict[str, Any]:  # fmt: skip
    """The provenance document of one judge configuration."""
    params = {"temperature": 0, **(sampling or {})}
    if len(params) > MAX_PARAMS or any(not _PARAM.fullmatch(str(k)) for k in params):
        raise ValueError("sampling is at most 16 lower-case parameter names")
    return {
        "convention": CONVENTION,
        "model": model,
        "prompt_digest": text_digest(prompt),
        "rubric_digest": text_digest(rubric) if rubric is not None else None,
        "sampling": {str(k): _decimal(v) for k, v in sorted(params.items())},
    }


def check(doc: Any) -> list[str]:
    """Problems with *doc* as a judge provenance document (none: valid)."""
    if not isinstance(doc, dict) or doc.get("convention") != CONVENTION:
        return ["not an opentine.judge-provenance/1 document"]
    problems = [f"missing {name}" for name in FIELDS if name not in doc]
    if problems or set(doc) - set(FIELDS):
        return problems or ["unknown fields"]
    if not isinstance(doc["model"], str) or not 0 < len(doc["model"]) <= 256:
        problems.append("model is a 1..256 character name")
    if not isinstance(doc["prompt_digest"], str) or not _DIGEST.fullmatch(doc["prompt_digest"]):
        problems.append("prompt_digest is sha256: + 64 hex")
    rubric = doc["rubric_digest"]
    if rubric is not None and not (isinstance(rubric, str) and _DIGEST.fullmatch(rubric)):
        problems.append("rubric_digest is null or sha256: + 64 hex")
    sampling = doc["sampling"]
    if (
        not isinstance(sampling, dict)
        or len(sampling) > MAX_PARAMS
        or any(not _PARAM.fullmatch(str(k)) or not isinstance(v, str) for k, v in sampling.items())
    ):
        problems.append("sampling maps parameter names to decimal strings")
    return problems


def pin(doc: dict[str, Any]) -> str:
    """The ``scorer_version`` that pins *doc*."""
    problems = check(doc)
    if problems:
        raise ValueError(f"not a judge provenance document: {problems[0]}")
    return PREFIX + hashlib.sha256(canonical_json(doc)).hexdigest()


def matches(doc: Any, scorer_version: str) -> bool:
    """Whether *doc* is the provenance a verdict's signed ``scorer_version`` pins."""
    try:
        return pin(doc) == scorer_version
    except (ValueError, TypeError):
        return False


__all__ = ["CONVENTION", "FILE_NAME", "PREFIX", "build", "check", "matches", "pin",
           "text_digest"]  # fmt: skip
