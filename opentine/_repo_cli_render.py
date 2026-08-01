"""Human rendering for the v3 repository read verbs.

Every string these renderers place on a terminal originates in a repository
payload, which is *recorded content*: prompts, tool names, model strings, and
object ids an attacker may have chosen. All of them go through
``opentine._cli_common._terminal``, which strips terminal control bytes and
escapes Rich markup. Nothing here interpolates a payload value raw.
"""

from __future__ import annotations

from typing import Any

from opentine._cli_common import BRAND, BRAND_DIM, _cost_str, _display_value, _terminal
from opentine._cli_render import _print_run_tree

#: Digest characters kept by :func:`_short_oid`; twelve hex characters of SHA-256
#: is the same collision margin git's short hash trades on.
_DIGEST_CHARS = 12


def _short_oid(oid: Any) -> str:
    """Render ``type:sha256:<64 hex>`` as ``type:<12 hex>``, terminal-safe.

    ``Run.short_id``/``opentine.core.short_id`` slice the first twelve characters
    of an id. On a v3 oid that yields ``"run:sha256:"`` — identical for every
    object in the repository — so the v3 side needs its own shortener that drops
    the constant hash-name segment instead of the digest.
    """
    text = str(oid)
    parts = text.split(":")
    if len(parts) == 3 and parts[1] == "sha256":
        return _terminal(f"{parts[0]}:{parts[2][:_DIGEST_CHARS]}")
    return _terminal(text[: len("run:sha256:") + _DIGEST_CHARS])


def entry_kind(entry: Any) -> str:
    """The kind a log/context line shows: the payload's own, else the object type.

    Shared with ``opentine._repo_cli_json`` so the ``--json`` ``kind`` can never
    disagree with the kind printed on the human line.
    """
    payload = entry.payload
    if isinstance(payload, dict):
        kind = payload.get("kind")
        if isinstance(kind, str) and kind:
            return kind
    return str(entry.object_type)


def _number(value: Any) -> float | None:
    """A payload number only if it really is one; recorded fields are unchecked."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if number == number and abs(number) != float("inf") else None


def _context_detail(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    # Truncate first, escape second: slicing escaped text can strand a lone
    # backslash, and only the escaped result may ever reach the console.
    if model := payload.get("model"):
        parts.append(f"model=[dim]{_terminal(_display_value(model)[:48])}[/]")
    tool = payload.get("tool")
    if isinstance(tool, dict) and tool.get("name"):
        parts.append(f"tool=[dim]{_terminal(_display_value(tool['name'])[:48])}[/]")
    if (cost := _number(payload.get("cost"))) is not None and cost > 0:
        parts.append(f"[dim]{_cost_str(cost)}[/]")
    if (duration := _number(payload.get("duration"))) is not None and duration > 0:
        parts.append(f"[dim]{duration:.1f}s[/]")
    return "  ".join(parts)


def render_context(console: Any, event_id: str, entries: list[Any]) -> None:
    """Print a causal slice oldest-first, the order ``context_slice`` returns."""
    # highlight=False throughout: Rich's repr highlighter restyles anything that
    # looks like a number, path, or url, and every one of these lines is content
    # a recorded payload chose.
    console.print(
        f"\n[{BRAND}]# context[/] {_short_oid(event_id)}  "
        f"[dim]{len(entries)} object(s), oldest first[/]\n",
        highlight=False,
    )
    for entry in entries:
        payload = entry.payload if isinstance(entry.payload, dict) else {}
        detail = _context_detail(payload)
        console.print(
            f"  {_short_oid(entry.oid)}  [bold]{_terminal(entry_kind(entry))}[/]"
            + (f"  {detail}" if detail else ""),
            highlight=False,
        )
    console.print()


def render_log(console: Any, entries: list[Any]) -> None:
    """The pre-existing ``repo-log`` line: the full oid, then the kind.

    Full oid rather than :func:`_short_oid`, unchanged: this is the line whose
    output scripts already pipe into ``tine object``.
    """
    for entry in entries:
        console.print(f"{_terminal(entry.oid)} {_terminal(entry_kind(entry))}", highlight=False)


def render_repo_show(console: Any, run: Any, oid: str) -> None:
    """Render a v3 run with the compatibility tree, then name the object it came from.

    ``Repo.load_run`` returns the same ``Run`` the .tine side renders, so the tree
    is reused verbatim rather than reimplemented; the trailing line is the only v3
    fact the legacy tree cannot know. It shows the *short* oid — the full one is in
    ``--json`` — so the line never wraps at an 80-column width.
    """
    _print_run_tree(run)
    if oid:
        console.print(f"  [{BRAND_DIM}]object:[/] {_short_oid(oid)}")
