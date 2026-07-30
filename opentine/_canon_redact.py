"""Credential redaction, and the nesting bound every write-side walk shares.

Split out of ``_canon`` for the module line cap. Like ``_canon`` this module
imports only the standard library, so ``_canon`` importing *it* adds no edge to
the format/migration/signing layers and cannot create a cycle. The bound lives
here rather than in ``_canon`` for the same reason: this module is the leaf.
"""

from __future__ import annotations

import re
from typing import Any

#: Hard nesting bound for every write-side walk over caller data.
#:
#: The *format* bound is the reader's — ``kernel.validate_json_shape`` refuses
#: any artifact nested deeper than 512, and ``_artifact_io.assert_loadable``
#: still reports exactly that at save, in the message that names the fix. This
#: second, looser bound exists for a different reason: without it ``_redact``
#: below and ``_canon._jsonable`` recurse as deep as the caller's data and die
#: with ``RecursionError``, and *where* is interpreter-dependent. Before 3.12 a
#: comprehension got its own frame (PEP 709 inlined them in 3.12), so identical
#: input crossed the 1000-frame limit at ~495 levels on 3.11 and ~990 on 3.12+:
#: three CI legs failed on the declared support floor while the same step
#: recorded cleanly on 3.12, and ``asdict``'s deepcopy put a third boundary at
#: ~495 on 3.11 and 3.12 only.
#:
#: 768 is 1.5x the reader's bound, so nothing a ``.tine`` artifact could ever
#: hold comes near it and every refusal a savable-shaped run sees still comes
#: from the reader-symmetric check. It also leaves ~200 Python frames spare on
#: 3.11, the floor: both walks now cost exactly one frame per level, and the
#: stdlib JSON encoder ``_graph_serde.save_run`` uses dies at ~992 there.
MAX_CANONICAL_DEPTH = 768


def _too_deep() -> ValueError:
    """The single refusal both write-side walks raise, in the reader's language."""
    return ValueError(
        f"value nesting or structure exceeds the {MAX_CANONICAL_DEPTH}-level limit this "
        "build can encode on every supported interpreter; flatten the offending "
        "input before recording or saving it"
    )


_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _field_name(value: Any) -> str:
    # Quotes stripped so a JSON fragment in free text ('"api_key": "sk-…"') names
    # the same field as the bare form; v3 handles it, v2 stored the secret.
    return _CAMEL_BOUNDARY.sub("_", str(value).strip().strip("\"'")).lower().replace("-", "_")


def _secret_field(name: str, credential_names: set[str], suffixes: tuple[str, ...]) -> bool:
    candidates = (name, name[:-1]) if name.endswith("s") else (name,)
    compact_suffixes = tuple(suffix.replace("_", "") for suffix in suffixes)
    return any(
        item in credential_names
        or item.endswith(suffixes)
        or item.replace("_", "").endswith(compact_suffixes)
        for item in candidates
    )


def _split_assignment(text: str) -> tuple[str, str, str]:
    """Split on whichever of ``:``/``=`` comes *first*, not on whichever exists.

    A value may contain the other (``api_key=sk-proj:abc``); splitting on the later
    one buries the credential name in the label and leaks the secret.
    """
    at = min((i for i in (text.find(":"), text.find("=")) if i >= 0), default=-1)
    if at < 0:
        return text, "", ""
    return text[:at], text[at], text[at + 1 :]


def _redact(value: Any, _depth: int = 0) -> Any:
    """Redact credential fields without deleting numeric usage dimensions.

    ``_depth`` is the same bound ``_jsonable`` enforces, and for the same reason:
    this walk is the entrance to ``save_run`` (via ``run_to_dict``) and to
    ``Repo.put``, so unbounded it turned a deeply nested tool result into a
    ``RecursionError`` on *every* interpreter instead of a refusal a caller can
    act on. Cycles land here too — a self-referential dict is infinitely deep.
    """
    if _depth > MAX_CANONICAL_DEPTH:
        raise _too_deep()
    credential_names = set(
        (
            "api_key apikey api_token access_key secret_access_key secret_key access_token "
            "refresh_token auth_token bearer_token id_token session_token password passwd "
            "passphrase secret client_secret private_key credential credentials authorization "
            "proxy_authorization cookie set_cookie"
        ).split()
    )
    suffixes = (
        "_api_key",
        "_api_token",
        "_access_key",
        "_access_token",
        "_authorization",
        "_auth_token",
        "_bearer_token",
        "_client_secret",
        "_cookie",
        "_credential",
        "_credentials",
        "_id_token",
        "_passphrase",
        "_password",
        "_passwd",
        "_private_key",
        "_proxy_authorization",
        "_refresh_token",
        "_secret",
        "_session_token",
        "_secret_key",
        "_set_cookie",
    )
    if isinstance(value, dict):
        header_names = [item for key, item in value.items() if _field_name(key) == "name"]
        header_values = {key for key in value if _field_name(key) == "value"}
        secret_header = any(
            isinstance(item, str)
            and (
                _field_name(item) == "token"
                or _secret_field(_field_name(item), credential_names, suffixes)
            )
            for item in header_names
        )
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            name = _field_name(key)
            is_secret = _secret_field(name, credential_names, suffixes) or (
                key in header_values and secret_header
            )
            if name == "token" and not isinstance(item, (int, float)):
                is_secret = True
            redacted[key] = "[REDACTED]" if is_secret else _redact(item, _depth + 1)
        return redacted
    if isinstance(value, (list, tuple)):
        items = list(value)
        headers = {"authorization", "proxy_authorization", "cookie", "set_cookie"}
        if len(items) == 2 and isinstance(items[0], str):
            name = _field_name(items[0])
            if (
                name == "token"
                or name in headers
                or _secret_field(name, credential_names, suffixes)
            ):
                return [items[0], "[REDACTED]"]
        redacted = []
        for item in items:
            if isinstance(item, str) and (":" in item or "=" in item):
                name, separator, _ = _split_assignment(item)
                if _field_name(name) in headers | {"token"}:
                    redacted.append(name + separator + " [REDACTED]")
                    continue
            redacted.append(_redact(item, _depth + 1))
        return redacted
    if isinstance(value, str) and (":" in value or "=" in value):
        label, separator, candidate = _split_assignment(value)
        name = _field_name(label)
        headers = {"authorization", "proxy_authorization", "cookie", "set_cookie"}
        words = candidate.strip().casefold().split()
        questions = {"can", "could", "how", "should", "what", "when", "where", "which", "why"}
        articles = {"a", "an", "the", "this"}
        header_nouns = {"field", "header", "label", "setting", "value"}
        prose = bool(words) and (
            words[0] in questions
            or (len(words) > 1 and words[0] in articles and words[1] in header_nouns)
        )
        # Bare "token" is not a credential name (counters must survive), but a
        # *quoted* value is no counter — same rule the dict branch applies.
        if name in headers or (name == "token" and candidate.strip()[:1] in {'"', "'"}):
            return label + separator + " [REDACTED]"
        if _secret_field(name, credential_names, suffixes) and not prose:
            return label + separator + " [REDACTED]"
    return value
