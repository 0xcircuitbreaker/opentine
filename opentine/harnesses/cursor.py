"""Cursor Agent CLI harness (``agent --print --output-format stream-json``).

Cursor's CLI binary is ``agent`` (installed as ``cursor-agent`` by older
releases; pass ``--harness-command`` for those). Its stream reports the model's
display name, assistant messages and tool calls, but no token usage, so a
Cursor run records what happened without being priceable.
"""

from opentine.harnesses._harness_catalog import HARNESS_CLASSES

CursorHarness = HARNESS_CLASSES["cursor"]

__all__ = ["CursorHarness"]
