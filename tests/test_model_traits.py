"""Model wire rules live in one table and fail safe for models not yet listed.

Each new family used to slip past a per-adapter name list (0.8.2: claude-opus-5
and gpt-6-* were sent a temperature their APIs reject with HTTP 400). Omitting a
sampling parameter never fails a request, so an unlisted Claude or native OpenAI
model now gets none, while every listed model keeps its exact behaviour.
"""

from __future__ import annotations

import pytest

from opentine.models._anthropic_rules import model_rules
from opentine.models._responses import omits_temperature
from opentine.models.anthropic import Anthropic
from opentine.models.openai import OpenAI

# (supports_thinking, restricted_sampling, explicit_adaptive), unchanged from 0.8.2.
KNOWN_CLAUDE = {
    "claude-2.1": (False, False, False),
    "claude-3-5-haiku-20241022": (False, False, False),
    "claude-3-7-sonnet-20250219": (True, False, False),
    "claude-haiku-4-5-20251001": (False, False, False),
    "claude-opus-4-0": (True, False, False),
    "claude-opus-4-1-20250805": (True, False, False),
    "claude-opus-4-20250514": (True, False, False),
    "claude-sonnet-4-5": (True, False, False),
    "claude-opus-4.5": (True, False, False),
    "claude-sonnet-4-6": (True, True, True),
    "claude-opus-4-8": (True, True, True),
    "claude-opus-5": (True, True, False),
    "claude-opus-5-5": (True, True, False),
    "claude-sonnet-5.5": (True, True, False),
    "claude-haiku-5-5": (True, True, False),
    "claude-fable-5-1": (True, True, False),
    "claude-mythos-preview": (True, True, False),
}


@pytest.mark.parametrize(("model", "rules"), KNOWN_CLAUDE.items())
def test_every_listed_claude_model_keeps_its_rules(model, rules):
    assert model_rules(model) == rules


@pytest.mark.parametrize(
    "model", ["claude-opus-6", "claude-sonnet-6-1", "claude-haiku-6", "claude-opus-4-10"]
)
def test_an_unlisted_claude_model_is_sent_no_sampling_parameters(model):
    assert model_rules(model)[1] is True
    assert "temperature" not in Anthropic(model)._kwargs([], None, None, 0.0)


@pytest.mark.parametrize("model", ["glm-5.3", "kimi-k3", "deepseek-v4-pro"])
def test_a_foreign_model_behind_the_anthropic_adapter_keeps_its_temperature(model):
    assert "temperature" in Anthropic(model)._kwargs([], None, None, 0.0)


@pytest.mark.parametrize(
    ("model", "native", "compatible"),
    [
        ("gpt-4o", False, False),
        ("gpt-4.1-mini", False, False),
        ("gpt-3.5-turbo", False, False),
        ("chatgpt-4o-latest", False, False),
        ("ft:gpt-4o-mini:org::abc", False, False),
        ("o3-mini", True, True),
        ("gpt-5.6-sol", True, True),
        ("gpt-6.1-sol", True, True),
        # Unlisted: the native API fails safe, an arbitrary endpoint does not guess.
        ("gpt-7", True, False),
        ("codex-mini-latest", True, False),
    ],
)
def test_openai_temperature_rules(model, native, compatible):
    assert omits_temperature(model) is native
    assert omits_temperature(model, native=False) is compatible
    local = OpenAI(model, api_key="k", base_url="http://localhost:8000/v1")
    assert ("temperature" in local._kwargs([], None, None, 0.0)) is not compatible
