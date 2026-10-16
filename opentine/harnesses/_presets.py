"""Table-driven presets for CLI-shaped agent harnesses.

Most terminal coding agents differ from each other only in the command that starts
a non-interactive run; the JSON-or-text parsing in :class:`JSONOrTextHarness` is
already shared. So a preset here is a data row, not a class body — supporting one
more tool costs a line rather than a ~12-line subclass, which is what keeps these
modules inside the 250-line architecture gate as the ecosystem keeps growing.

Only tools whose non-interactive invocation is documented get a row. A preset whose
command was guessed is worse than no preset: it fails at spawn time with a confusing
error instead of letting the user reach for ``--harness generic --harness-command``,
which already runs anything.

The table itself now lives in ``_harness_catalog`` (one row per CLI, with the
event dialect that makes its runs priceable); :func:`preset` remains for
callers that build their own text-mode preset.
"""

from __future__ import annotations

from opentine.harnesses._harness_catalog import HARNESS_CLASSES
from opentine.harnesses.agent_cli import JSONOrTextHarness


def preset(
    harness: str,
    command: tuple[str, ...],
    *,
    doc: str,
    login_env_keys: tuple[str, ...] = (),
) -> type[JSONOrTextHarness]:
    """Build a harness class from one row of the table below."""
    return type(
        f"{harness.title().replace('-', '')}Harness",
        (JSONOrTextHarness,),
        {
            "__doc__": doc,
            "name": harness,
            "default_command": command,
            "login_env_keys": login_env_keys,
            "model_info": property(lambda self, _label=harness: _label),
        },
    )


#: Kept as names for code written against 0.9: both now come from the catalog,
#: which reads their documented JSON modes (``_harness_catalog``).
GeminiCLIHarness = HARNESS_CLASSES["gemini"]
GrokBuildHarness = HARNESS_CLASSES["grok"]

__all__ = ["GeminiCLIHarness", "GrokBuildHarness", "preset"]
