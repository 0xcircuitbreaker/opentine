"""Private-key masking for a harness's output stream, before any sink sees it.

Each stdout line became its own step and was redacted alone, but the record's
PEM scrubber needs the ``BEGIN`` marker in the same string as the key body: a
key the agent printed (``cat ~/.ssh/id_ed25519``) lost its marker line and kept
every body line verbatim in the record (audit 0.10, C3-2). :class:`KeyLines`
remembers an open block across raw text lines.

The rule that keeps this from ever recording *less* than the scrubber would:
a marker is never removed on its own. Inside one string (a JSON event's value)
the whole span from ``BEGIN`` to the nearest ``END`` -- or to the end of the
string when there is none -- becomes the scrubber's own label. Cutting the
marker and then judging each following line as "key material or not" let a
``git diff`` (``-MIIE…``), ``cat -A`` (``…$``) or source-code (``"MIIE…\\n" +``)
body through with nothing left for the scrubber to anchor on (final pass, #9).
"""

from __future__ import annotations

import json
from collections.abc import Callable

from opentine.harnesses._key_b64 import is_wrapped_body, wrapped_key
from opentine.harnesses._key_decor import DATA as _DATA
from opentine.harnesses._key_decor import HEADER as _HEADER
from opentine.harnesses._key_decor import key_body as _key_body
from opentine.harnesses._key_json import JsonKeys, masked_text, open_after, walk_strings
from opentine.harnesses._key_patterns import BEGIN as _BEGIN
from opentine.harnesses._key_patterns import END as _END
from opentine.harnesses._key_patterns import PLACEHOLDER
from opentine.harnesses._types import loads_event
from opentine.kernel import MAX_JSON_DEPTH, KernelError, validate_json_shape

_NOT_JSON = object()
_B64_HINT = "LS0tLS1CRUdJTi"  # "-----BEGIN" base64-encoded


def _json_value(text: str) -> object:
    """*text* decoded as JSON, within the reader's depth bound, else ``_NOT_JSON``."""
    try:
        if text.count("[") + text.count("{") > MAX_JSON_DEPTH:
            # Past the reader's depth bound a line is text, never an event (the
            # rule ``parse_json_event`` applies), and re-serializing one that
            # deep raised ``RecursionError`` on 3.11 (re-audit round 3, #4).
            validate_json_shape(text, max_tokens=len(text) + 1)
        return loads_event(text)
    except (ValueError, RecursionError, KernelError):
        return _NOT_JSON


def _json_event(line: str) -> object:
    """*line* decoded if it is a JSON document (a CLI's structured event).

    Masking one as text cut it mid-string: the event no longer parsed and its
    usage, cost and tool calls fell out of the record (re-audit #17).
    """
    stripped = line.strip()
    if not stripped.startswith(("{", "[")):
        return _NOT_JSON
    return _json_value(stripped)


def _map_strings(event: object, mask: Callable[[str], str]) -> object:
    """*event* with *mask* applied to every string value (keys: :func:`masked_text`)."""
    return walk_strings(event, lambda _path, text: mask(text))


def _dumps(value: object) -> str | None:
    try:
        # ASCII escapes: a decoded lone surrogate must not reach the UTF-8 record.
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    except (ValueError, RecursionError):
        return None


def _fragment(line: str, mask: Callable[[str], str]) -> str | None:
    """A pretty-printed JSON document's line (``"k": "v",``) re-emitted masked.

    A multi-line ``--json`` envelope (openclaw, droid, auggie) is parsed only once
    all its lines are joined; cutting one member line at a marker dropped its
    closing quote, the document no longer parsed and the CLI's cost and usage
    vanished (final pass, #10). Masking inside the member keeps it valid JSON.
    """
    body = line.strip()
    comma = body.endswith(",")
    core = body[:-1].rstrip() if comma else body
    if not core:
        return None
    for text, member in ((core, False), ("{" + core + "}", True)):
        value = _json_value(text)
        if value is _NOT_JSON or (member and not isinstance(value, dict)):
            continue
        dumped = _dumps(_map_strings(value, mask))
        if dumped is None:
            return None
        inner = dumped[1:-1] if member else dumped
        return line[: len(line) - len(line.lstrip())] + inner + ("," if comma else "")
    return None


class KeyLines:
    """Mask private-key material that spans several lines of one stream."""

    def __init__(self) -> None:
        self.open = False
        self.wrapped = False  # inside a base64-wrapped key (``base64 id_rsa``)
        self.events = JsonKeys()  # a block spanning JSON delta events
        #: The last line was a JSON document (or member line), masked in place.
        self.structured = False

    def mask(self, line: str) -> str:
        self.events.tick()
        self.structured = False
        if self.wrapped:
            if is_wrapped_body(_key_body(line)) and _json_event(line) is _NOT_JSON:
                return PLACEHOLDER
            self.wrapped = False
        if self.events.wants(line):
            event = _json_event(line)
            if event is not _NOT_JSON:
                return self._event(line, event)
        if self.open:
            return self._continue(line)
        if _BEGIN.search(line) is None:
            return self._wrapped(line) if _B64_HINT in line else line
        fragment = _fragment(line, masked_text)
        if fragment is not None:
            self.open = open_after(line)
            self.structured = True
            return fragment
        return self._text(line)

    def _event(self, line: str, event: object) -> str:
        # Keep the event parseable; mask inside its strings -- following a block
        # opened by an earlier delta event -- and keep masking raw key lines that
        # follow it in the stream while its block is open.
        result = self.events.mask(event)
        self.open = self.events.open or self.events.raw_open
        self.structured = True
        if not self.events.changed:
            return line  # nothing to mask: the CLI's own bytes, untouched
        masked = _dumps(result)
        return self._text(line) if masked is None else masked

    def _continue(self, line: str) -> str:
        event = _json_event(line)
        if event is not _NOT_JSON:
            self.open = False
            return self._event(line, event)
        body = _key_body(line)
        if _END.search(line):
            self.open = False
        elif body and not _HEADER.match(body) and not _DATA.fullmatch(body):
            self.open = False
            return line
        if not line.strip():
            return line
        # A JSON document's member line stays valid JSON (final pass, #10).
        fragment = _fragment(line, lambda _value: PLACEHOLDER)
        self.structured = fragment is not None
        return fragment or PLACEHOLDER

    def _wrapped(self, line: str) -> str:
        if _json_event(line) is not _NOT_JSON:
            return line  # one string: the record's scrubber sees the whole key
        found = wrapped_key(line)
        if found is None:
            return line
        start, whole = found
        self.wrapped = not whole
        return line[:start] + PLACEHOLDER

    def _text(self, line: str) -> str:
        # The LAST marker decides: a whole block followed by a second, unterminated
        # one on the same line left the body after it verbatim when only the
        # first marker was checked (re-audit round 3, #5).
        last_end = max((m.end() for m in _END.finditer(line)), default=-1)
        open_at = next((m for m in _BEGIN.finditer(line) if m.end() > last_end), None)
        if open_at is None:
            return line  # whole blocks on one line: the record's scrubber has them
        self.open = True
        return line[: open_at.start()] + PLACEHOLDER


def buffered(keys: KeyLines, raw: str, masked: str) -> str:
    """The form of a line kept for the stream's joined output (the done step).

    Line-wise masking cut the ``BEGIN`` line to a placeholder; when it then
    misjudged a decorated body line as prose, the joined output kept that body
    with no marker left for the record's scrubber to anchor on -- *less* redacted
    than the raw text (final pass 5, #9). A raw text line holding a ``BEGIN`` or
    ``END`` marker therefore stays raw there, so the scrubber still sees the
    block's bounds and removes everything between them; every other line, and
    every JSON event, keeps its masked form.
    """
    if keys.structured or masked == raw:
        return masked
    return raw if _BEGIN.search(raw) or _END.search(raw) else masked


__all__ = ["PLACEHOLDER", "KeyLines", "buffered", "masked_text"]
