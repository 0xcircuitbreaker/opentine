"""The optional local classifier layer of ``opentine-redaction/3`` (0.46).

Patterns find what has a shape; a classifier finds what has a meaning (a
person's name, a date of birth). The layer is pluggable and always local:

* ``rules`` (the default, ``rules/1``) is :class:`RuleClassifier`, a small
  cue-word classifier shipped here: standard library, deterministic.
* ``none`` turns the layer off.
* ``MODULE:ATTR`` names a Python object importable on this machine -- for
  example an adapter around a local spaCy or ONNX NER model (docs/PII.md). It
  must have a ``name`` and a ``classify(text)`` returning ``(start, end, kind)``
  triples. A spec that looks like a URL is refused: the layer never sends text
  anywhere, and no option makes it.

``OPENTINE_PII_CLASSIFIER`` supplies the spec when no ``--classifier`` is given.
"""

from __future__ import annotations

import importlib
import os
import re
from typing import Protocol, runtime_checkable

ENV = "OPENTINE_PII_CLASSIFIER"
_NAME = re.compile(r"[A-Za-z0-9_.:/@+-]{1,64}")
_SPEC = re.compile(r"[A-Za-z_][\w.]*:[A-Za-z_]\w*")


@runtime_checkable
class Classifier(Protocol):
    """A local PII classifier: ``classify`` returns ``(start, end, kind)`` spans."""

    name: str

    def classify(self, text: str) -> list[tuple[int, int, str]]: ...


_CAP = r"[A-Z][a-z'\-]{1,30}"
_TITLE = r"(?:Mr|Mrs|Ms|Mx|Dr|Prof)\.?"
_PERSON = re.compile(
    r"(?:\b(?:[Mm]y name is|[Nn]ame:|[Dd]ear|[Ss]igned,?|[Pp]atient:|[Cc]ustomer:)\s+"
    rf"(?:{_TITLE}\s+)?|\b{_TITLE}\s+)"
    rf"({_CAP}(?:\s+{_CAP}){{0,2}})"
)
_DATE = r"\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{2}-\d{2}|\d{1,2} [A-Z][a-z]{2,8} \d{4}"
_DOB = re.compile(rf"\b(?:DOB|D\.O\.B\.|[Dd]ate of birth|[Bb]orn on|[Bb]irthday)\s*:?\s*({_DATE})")


class RuleClassifier:
    """``rules/1``: names after a cue word or an honorific; dates after a birth cue."""

    name = "rules/1"

    def classify(self, text: str) -> list[tuple[int, int, str]]:
        spans = [(m.start(1), m.end(1), "person") for m in _PERSON.finditer(text)]
        spans += [(m.start(1), m.end(1), "dob") for m in _DOB.finditer(text)]
        return sorted(spans)


def load(spec: str | None = None) -> Classifier | None:
    """The classifier a spec names (``rules``, ``none`` or ``MODULE:ATTR``)."""
    spec = (spec if spec is not None else os.environ.get(ENV, "rules")).strip()
    if spec in {"", "rules", "rules/1"}:
        return RuleClassifier()
    if spec == "none":
        return None
    if "://" in spec or not _SPEC.fullmatch(spec):
        raise ValueError(
            f"classifier {spec!r} is not rules, none or MODULE:ATTR; "
            "the PII classifier runs locally only"
        )
    module, _, attr = spec.partition(":")
    found = getattr(importlib.import_module(module), attr)
    found = found() if isinstance(found, type) else found
    if not isinstance(found, Classifier) or not _NAME.fullmatch(str(found.name)):
        raise ValueError(f"{spec} has no usable name and classify(text)")
    return found


def name_of(classifier: Classifier | None) -> str:
    return "none" if classifier is None else str(classifier.name)


__all__ = ["ENV", "Classifier", "RuleClassifier", "load", "name_of"]
