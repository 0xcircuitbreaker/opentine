"""Live integration tests — run against a real model provider.

NOT run in CI. Requires an API key. Run manually with:

  uv run pytest tests/test_live.py -v --provider anthropic
  uv run pytest tests/test_live.py -v --provider openai
  uv run pytest tests/test_live.py -v --provider google
  uv run pytest tests/test_live.py -v --provider ollama
  uv run pytest tests/test_live.py -v --provider kimi
  uv run pytest tests/test_live.py -v --provider deepseek
  uv run pytest tests/test_live.py -v --provider glm
  uv run pytest tests/test_live.py -v --provider groq

Or just pick whichever you have a key for:

  $env:ANTHROPIC_API_KEY="sk-ant-..."
  uv run pytest tests/test_live.py -v --provider anthropic
"""

from __future__ import annotations

import json
import os

import pytest

from opentine import Agent, Run, RunStatus, StepKind

# ---------------------------------------------------------------------------
# Provider setup
# ---------------------------------------------------------------------------

PROVIDERS = {
    "anthropic": (
        "opentine.models.anthropic",
        "Anthropic",
        "claude-sonnet-4-20250514",
        "ANTHROPIC_API_KEY",
    ),
    "openai": ("opentine.models.openai", "OpenAI", "gpt-4o", "OPENAI_API_KEY"),
    "google": ("opentine.models.google", "Google", "gemini-2.0-flash", "GOOGLE_API_KEY"),
    "ollama": ("opentine.models.ollama", "Ollama", "llama3.1", None),
    "kimi": ("opentine.models.compat", "Kimi", "moonshot-v1-8k", "KIMI_API_KEY"),
    "deepseek": ("opentine.models.compat", "DeepSeek", "deepseek-chat", "DEEPSEEK_API_KEY"),
    "glm": ("opentine.models.compat", "GLM", "glm-4-flash", "GLM_API_KEY"),
    "groq": ("opentine.models.compat", "Groq", "llama-3.1-70b-versatile", "GROQ_API_KEY"),
    "together": (
        "opentine.models.compat",
        "Together",
        "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        "TOGETHER_API_KEY",
    ),
    "mistral": ("opentine.models.compat", "Mistral", "mistral-large-latest", "MISTRAL_API_KEY"),
    "qwen": ("opentine.models.compat", "Qwen", "qwen-plus", "QWEN_API_KEY"),
}


@pytest.fixture
def provider(request):
    name = request.config.getoption("--provider")
    if name not in PROVIDERS:
        pytest.skip(f"Unknown provider: {name}. Choose from: {list(PROVIDERS.keys())}")
    return name


@pytest.fixture
def model(provider):
    module_path, class_name, default_model, env_key = PROVIDERS[provider]
    if env_key and not os.environ.get(env_key):
        pytest.skip(f"Set {env_key} env var to run live tests with {provider}")
    import importlib

    mod = importlib.import_module(module_path)
    adapter_cls = getattr(mod, class_name)
    return adapter_cls(default_model)


@pytest.fixture
def agent(model):
    return Agent(model=model, system="Answer concisely in one sentence.", max_steps=5)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLiveCompletion:
    """Basic completion — does the model respond?"""

    def test_simple_prompt(self, agent, tmp_path):
        run = agent.run_sync("What is 2 + 2?")
        assert run.status == RunStatus.completed
        assert len(run.steps) >= 1
        assert run.steps[-1].kind == StepKind.done

        # Verify the response contains something
        text = run.steps[-1].inputs.get("text", "")
        assert len(text) > 0
        print(f"\n  Response: {text[:100]}")
        print(f"  Steps: {len(run.steps)}, Cost: ${run.total_cost:.4f}")

    def test_run_has_model_info(self, agent):
        run = agent.run_sync("Say hello")
        assert run.model_info != ""
        assert run.model_info != "mock-model"
        print(f"\n  Model: {run.model_info}")

    def test_cost_is_tracked(self, agent, provider):
        run = agent.run_sync("Say ok")
        if provider == "ollama":
            assert run.total_cost == 0.0  # local models are free
        else:
            # Cloud providers should report some cost
            print(f"\n  Cost: ${run.total_cost:.6f}")


class TestLiveSaveLoad:
    """Serialization roundtrip with real model output."""

    def test_save_and_load(self, agent, tmp_path):
        run = agent.run_sync("What color is the sky?")
        path = tmp_path / "live_test.tine"
        run.save(path)

        loaded = Run.load(path)
        assert loaded.id == run.id
        assert loaded.status == run.status
        assert len(loaded.steps) == len(run.steps)
        assert loaded.model_info == run.model_info
        assert loaded.steps[-1].inputs["text"] == run.steps[-1].inputs["text"]

    def test_tine_file_is_valid_json(self, agent, tmp_path):
        run = agent.run_sync("Say yes")
        path = tmp_path / "json_test.tine"
        run.save(path)

        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["id"] == run.id
        assert len(data["steps"]) == len(run.steps)


class TestLiveFork:
    """Fork a real model run."""

    def test_fork_preserves_content(self, agent, tmp_path):
        run = agent.run_sync("Name three colors")
        assert len(run.steps) >= 1

        forked = run.fork(run.steps[0].id, new_run_id="forked_live")
        assert forked.id == "forked_live"
        assert len(forked.steps) == 1
        assert forked.steps[0].inputs == run.steps[0].inputs
        assert forked.metadata["forked_from"] == run.id

        # Save and reload the fork
        path = tmp_path / "forked.tine"
        forked.save(path)
        reloaded = Run.load(path)
        assert reloaded.metadata["forked_from"] == run.id


class TestLiveDiff:
    """Run two prompts and verify they produce different results."""

    def test_different_prompts_differ(self, agent):
        run_a = agent.run_sync("What is 2 + 2?")
        run_b = agent.run_sync("What is the capital of France?")

        # Different prompts should produce different step content
        text_a = run_a.steps[-1].inputs.get("text", "")
        text_b = run_b.steps[-1].inputs.get("text", "")
        assert text_a != text_b
        print(f"\n  A: {text_a[:60]}")
        print(f"  B: {text_b[:60]}")
