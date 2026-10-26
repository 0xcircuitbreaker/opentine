"""``opentine-agent/1``: which agent produced a run, as a content-addressed record.

A run's ``metadata.agent_identity`` holds one record::

    {"scheme": "opentine-agent/1", "harness", "harness_version",
     "definition_digest", "model", "provider", "key_fpr",
     "instance", "parent", "parent_run", "spawn_step"}

The **agent ref** is ``agt_`` + 32 hex (128 bits) of SHA-256 over the stable
fields only -- harness, definition digest, model and signing-key fingerprint --
so every run of the same agent shares it, while ``instance`` (a per-run nonce)
tells concurrent copies apart and ``parent``/``parent_run``/``spawn_step`` give
subagent lineage.

A record is a **claim**: any run can write any ref. Only a verified
``tine-actions/1`` manifest (``_actions_manifest``) turns it into evidence.
Refs are always compared at full length with ``hmac.compare_digest``; a prefix
is never accepted as a ref, so grinding a short look-alike prefix buys nothing.
Names are NFKC-normalised before hashing, and a name that is not plain ASCII
after that is flagged as a possible look-alike wherever it is shown.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata
from typing import Any

from opentine.kernel import KernelError, canonical_json

SCHEME = "opentine-agent/1"
DOMAIN = b"opentine.agent.v1:"
REF_RE = re.compile(r"agt_[0-9a-f]{32}")
FPR_RE = re.compile(r"sha256:[0-9a-f]{64}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
NONCE_RE = re.compile(r"[0-9a-f]{32}")
STABLE_FIELDS = ("harness", "definition_digest", "model", "key_fpr")
TEXT_FIELDS = ("harness", "harness_version", "model", "provider")
FIELDS = (
    "scheme",
    *TEXT_FIELDS,
    "definition_digest",
    "key_fpr",
    "instance",
    "parent",
    "parent_run",
    "spawn_step",
)
MAX_TEXT = 128
LEGACY_PREFIX = "legacy:"


class IdentityError(ValueError):
    pass


def normalize_name(value: Any) -> str:
    """NFKC, stripped, controls removed, bounded: the spelling that gets hashed."""
    if not isinstance(value, str):
        return ""
    text = unicodedata.normalize("NFKC", value).strip()
    text = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")
    return text[:MAX_TEXT]


def lookalike(value: Any) -> bool:
    """True when *value* is not plain printable ASCII after normalisation."""
    return isinstance(value, str) and not normalize_name(value).isascii()


def agent_ref(record: dict[str, Any]) -> str:
    """The stable ``agt_`` ref of a (validated) record."""
    stable = {name: record.get(name, "") for name in STABLE_FIELDS}
    digest = hashlib.sha256(DOMAIN + canonical_json(stable)).hexdigest()
    return "agt_" + digest[:32]


def build(
    *,
    harness: str,
    model: str = "",
    provider: str = "",
    harness_version: str = "",
    definition_digest: str = "",
    key_fpr: str = "",
    instance: str = "",
    parent: str = "",
    parent_run: str = "",
    spawn_step: str = "",
) -> dict[str, Any]:
    """A validated record; text fields are normalised, never guessed."""
    record = {
        "scheme": SCHEME,
        "harness": normalize_name(harness),
        "harness_version": normalize_name(harness_version),
        "model": normalize_name(model),
        "provider": normalize_name(provider),
        "definition_digest": definition_digest,
        "key_fpr": key_fpr,
        "instance": instance,
        "parent": parent,
        "parent_run": normalize_name(parent_run),
        "spawn_step": normalize_name(spawn_step),
    }
    return validate(record)


def validate(record: Any) -> dict[str, Any]:
    """*record* checked field by field; raises :class:`IdentityError`."""
    if not isinstance(record, dict) or record.get("scheme") != SCHEME:
        raise IdentityError("not an opentine-agent/1 record")
    if set(record) - set(FIELDS):
        raise IdentityError("unknown field in agent identity")
    out: dict[str, Any] = {"scheme": SCHEME}
    for name in FIELDS[1:]:
        value = record.get(name, "")
        if not isinstance(value, str) or len(value) > MAX_TEXT:
            raise IdentityError(f"agent identity field {name!r} must be a short string")
        out[name] = value
    if not out["harness"]:
        raise IdentityError("agent identity needs a harness")
    for name in (*TEXT_FIELDS, "parent_run", "spawn_step"):
        if out[name] != normalize_name(out[name]):
            raise IdentityError(f"agent identity field {name!r} is not normalised")
    for name, pattern in (
        ("definition_digest", DIGEST_RE),
        ("key_fpr", FPR_RE),
        ("instance", NONCE_RE),
        ("parent", REF_RE),
    ):
        if out[name] and not pattern.fullmatch(out[name]):
            raise IdentityError(f"agent identity field {name!r} is malformed")
    return out


def run_identity(run: Any) -> dict[str, Any] | None:
    """The run's validated record, or ``None`` (absent or malformed: a legacy run)."""
    metadata = getattr(run, "metadata", None)
    record = metadata.get("agent_identity") if isinstance(metadata, dict) else None
    try:
        return validate(record) if record is not None else None
    except (IdentityError, KernelError):
        return None


def run_agent_ref(run: Any) -> str:
    """``agt_...`` for a run with a record, else ``legacy:<label>`` (maybe ``legacy:``)."""
    record = run_identity(run)
    if record is not None:
        return agent_ref(record)
    from opentine._index_types import run_agent

    return LEGACY_PREFIX + normalize_name(run_agent(run))


def same_ref(left: Any, right: Any) -> bool:
    """Full-length, constant-time equality of two refs; never a prefix match."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def check_query_ref(value: str) -> str:
    """A ref given on the command line: a full ``agt_`` ref or a ``legacy:`` label."""
    text = value.strip()
    if text.startswith(LEGACY_PREFIX):
        return LEGACY_PREFIX + normalize_name(text[len(LEGACY_PREFIX) :])
    if not REF_RE.fullmatch(text):
        raise IdentityError(
            f"{value!r} is not a full agent ref: give all of agt_ + 32 hex "
            "(prefixes are refused, they can be ground to collide)"
        )
    return text


__all__ = [
    "SCHEME",
    "IdentityError",
    "agent_ref",
    "build",
    "check_query_ref",
    "lookalike",
    "normalize_name",
    "run_agent_ref",
    "run_identity",
    "same_ref",
    "validate",
]
