"""Adapters that let opentine track external agent harnesses."""

from opentine.harnesses.base import HarnessAdapter, HarnessStep, OpentineHarness, ProcessHarness
from opentine.harnesses.claude_code import ClaudeCodeHarness
from opentine.harnesses.codex import CodexCLIHarness
from opentine.harnesses.cursor import CursorHarness
from opentine.harnesses.openai_agents import OpenAIAgentsHarness

__all__ = [
    "ClaudeCodeHarness",
    "CodexCLIHarness",
    "CursorHarness",
    "HarnessAdapter",
    "HarnessStep",
    "OpenAIAgentsHarness",
    "OpentineHarness",
    "ProcessHarness",
]
