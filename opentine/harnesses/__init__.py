"""Adapters that let opentine track external agent harnesses."""

from opentine.harnesses._harness_catalog import HARNESS_CLASSES
from opentine.harnesses._presets import GeminiCLIHarness, GrokBuildHarness
from opentine.harnesses.agent_cli import GenericHarness
from opentine.harnesses.base import HarnessAdapter, HarnessStep, OpentineHarness, ProcessHarness
from opentine.harnesses.claude_code import ClaudeCodeHarness
from opentine.harnesses.codex import CodexCLIHarness
from opentine.harnesses.cursor import CursorHarness
from opentine.harnesses.openai_agents import OpenAIAgentsHarness

HermesHarness = HARNESS_CLASSES["hermes"]
KimiCodeHarness = HARNESS_CLASSES["kimi-code"]
OpenClawHarness = HARNESS_CLASSES["openclaw"]
OpenCodeHarness = HARNESS_CLASSES["opencode"]
PiHarness = HARNESS_CLASSES["pi"]
QwenCodeHarness = HARNESS_CLASSES["qwen-code"]
GooseHarness = HARNESS_CLASSES["goose"]
AmpHarness = HARNESS_CLASSES["amp"]
CopilotHarness = HARNESS_CLASSES["copilot"]
ClineHarness = HARNESS_CLASSES["cline"]

__all__ = [
    "AmpHarness",
    "ClaudeCodeHarness",
    "ClineHarness",
    "CopilotHarness",
    "CodexCLIHarness",
    "CursorHarness",
    "GeminiCLIHarness",
    "GenericHarness",
    "GooseHarness",
    "GrokBuildHarness",
    "HARNESS_CLASSES",
    "HarnessAdapter",
    "HermesHarness",
    "HarnessStep",
    "KimiCodeHarness",
    "OpenAIAgentsHarness",
    "OpenClawHarness",
    "OpenCodeHarness",
    "OpentineHarness",
    "PiHarness",
    "ProcessHarness",
    "QwenCodeHarness",
]
