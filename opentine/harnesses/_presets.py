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

Deliberately absent: Z.ai's ZCode ships as a desktop application with no documented
headless CLI, so there is no command to encode.
"""

from __future__ import annotations

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


#: xAI's terminal coding agent. ``grok exec`` is its documented one-shot mode: the
#: agent plans, executes, and exits. It documents no JSON output flag, which costs
#: nothing here — JSONOrTextHarness falls back to line-wise text capture.
GrokBuildHarness = preset(
    "grok",
    ("grok", "exec"),
    doc="Run xAI's Grok Build non-interactively through ``grok exec <task>``.",
)

#: Google's Gemini CLI. ``-p`` (``--prompt``) is its documented headless mode:
#: bypasses the interactive UI, prints one response to stdout, exits.
GeminiCLIHarness = preset(
    "gemini",
    ("gemini", "-p"),
    doc="Run Google's Gemini CLI in headless mode through ``gemini -p <task>``.",
)

__all__ = ["GeminiCLIHarness", "GrokBuildHarness", "preset"]
