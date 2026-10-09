"""Credential redaction, and the nesting bound every write-side walk shares.

Split out of ``_canon`` for the module line cap. Like ``_canon`` this module
imports only the standard library, so ``_canon`` importing *it* adds no edge to
the format/migration/signing layers and cannot create a cycle. The bound lives
here rather than in ``_canon`` for the same reason: this module is the leaf.
"""

from __future__ import annotations

import re
from typing import Any

from opentine._redact_extra import extra_secret_names
from opentine._redact_names import CREDENTIAL_NAMES, SECRET_SUFFIXES

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


_LOOSE_NAMES = frozenset({"pass", "auth"})
_AUTH_MODES = frozenset({"", "none", "basic", "bearer", "oauth", "oauth2", "api_key", "token"})


def _token_counter(name: str, value: Any) -> bool:
    """A number under a ``*token(s)`` name: a usage counter, never a credential.

    Compared with underscores removed, as ``_secret_field`` compares, so ``token``,
    ``max_tokens`` and ``maxtokens`` all keep their numbers.
    """
    if not name.replace("_", "").endswith(("token", "tokens")):
        return False
    # Token ids, {"tokens": [101, 2023, ...]}: one flat level, checked in a loop.
    items = value if isinstance(value, list | tuple) else (value,)
    for item in items:
        if isinstance(item, str):
            if not item.strip().replace(",", "").isdigit():
                return False
        elif isinstance(item, bool) or not isinstance(item, int | float):
            return False
    return True


def _split_assignment(text: str) -> tuple[str, str, str]:
    """Split on whichever of ``:``/``=`` comes *first*, not on whichever exists.

    A value may contain the other (``api_key=sk-proj:abc``); splitting on the later
    one buries the credential name in the label and leaks the secret.
    """
    at = min((i for i in (text.find(":"), text.find("=")) if i >= 0), default=-1)
    if at < 0:
        return text, "", ""
    return text[:at], text[at], text[at + 1 :]


#: Flag names whose *next* argv element is the credential (``--auth user:pw``).
_FLAG_NAMES = frozenset({"token", "pass", "auth"})


def _secret_flag(item: Any, credential_names: frozenset[str], suffixes: tuple[str, ...]) -> str:
    """The name of a ``--password``-style flag whose value is the next argv element.

    ``--password=hunter2`` was always caught as an assignment, but a recorded
    command is a list -- ``["cli", "--password", "hunter2"]`` -- and the value
    stood alone as its own element, with nothing to say what it was.
    """
    if not isinstance(item, str) or not item.startswith("-") or len(item) > 64:
        return ""
    if "=" in item or any(character.isspace() for character in item):
        return ""
    name = _field_name(item.lstrip("-"))
    return name if name in _FLAG_NAMES or _secret_field(name, credential_names, suffixes) else ""


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
    credential_names = CREDENTIAL_NAMES | extra_secret_names()
    suffixes = SECRET_SUFFIXES
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
            if is_secret and _token_counter(name, item):
                is_secret = False
            # The policy's own list (RedactionPolicy) names fields and holds none: kept
            # verbatim, or its first name would read as a ``[name, secret]`` pair.
            if name == "extra_secret_keys" and isinstance(item, list | tuple):
                if all(isinstance(entry, str) for entry in item):
                    redacted[key] = list(item)
                    continue
            # "pass" and "auth" are also flags ({"pass": true}, {"auth": "oauth2"}
            # is a mode); only a string under them can be the credential itself.
            if name in _LOOSE_NAMES and isinstance(item, str) and item not in _AUTH_MODES:
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
            ) and not _token_counter(name, items[1]):
                return [items[0], "[REDACTED]"]
        redacted = []
        flag = ""
        for item in items:
            if flag and isinstance(item, str) and not _token_counter(flag, item):
                redacted.append("[REDACTED]")
                flag = ""
                continue
            flag = _secret_flag(item, credential_names, suffixes)
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
        if (
            _secret_field(name, credential_names, suffixes)
            and not prose
            and not _token_counter(name, candidate)
        ):
            return label + separator + " [REDACTED]"
    return value
