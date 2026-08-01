"""Live integration tests — run against a real model provider.

NOT run in CI. Requires an API key. Run manually with:

  uv run pytest tests/test_live.py -v --provider anthropic
  uv run pytest tests/test_live.py -v --provider openai
  uv run pytest tests/test_live.py -v --provider google
  uv run pytest tests/test_live.py -v --provider ollama
  uv run pytest tests/test_live.py -v --provider kimi
  uv run pytest tests/test_live.py -v --provider deepseek
  uv run pytest tests/test_live.py -v --provider glm
  uv run pytest tests/test_live.py -v --provider lmstudio
  uv run pytest tests/test_live.py -v --provider groq
  uv run pytest tests/test_live.py -v --provider grok
  uv run pytest tests/test_live.py -v --provider ministral

Or just pick whichever you have a key for:

  $env:ANTHROPIC_API_KEY="sk-ant-..."
  uv run pytest tests/test_live.py -v --provider anthropic

MANAGED CLOUDS (the merge gate for `opentine.models.managed`). One smoke per
cloud, each guarded by both `--provider` and its credentials, so a machine
without them collects the test and SKIPS it. Nothing here shells a binary; the
cloud SDKs are called directly.

  # Bedrock — needs the `bedrock` extra and an AWS identity in the usual chain.
  export AWS_REGION=us-east-1 AWS_PROFILE=my-sso-profile
  uv run pytest tests/test_live.py -v --provider bedrock -k managed

  # Vertex — needs the `vertex` extra and Application Default Credentials.
  gcloud auth application-default login
  export GOOGLE_CLOUD_PROJECT=my-project GOOGLE_CLOUD_LOCATION=us-central1
  uv run pytest tests/test_live.py -v --provider vertex -k managed

  # Azure OpenAI — needs only the `compat` extra (the openai SDK).
  export AZURE_OPENAI_ENDPOINT=https://my-resource.openai.azure.com
  export AZURE_OPENAI_API_KEY=...            # or AZURE_OPENAI_TOKEN, an Entra bearer
  export AZURE_OPENAI_DEPLOYMENT=my-gpt-deployment
  uv run pytest tests/test_live.py -v --provider azure -k managed

Override the model per cloud with BEDROCK_MODEL / VERTEX_MODEL /
AZURE_OPENAI_DEPLOYMENT.
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

from opentine import Agent, Run, RunStatus, StepKind
from opentine.models._managed_billing import MANAGED_UNPRICED
from opentine.models.ollama import Ollama

pytestmark = pytest.mark.live

OLLAMA_VALIDATION_MODELS = ("llama3.1", "qwen3")

# ---------------------------------------------------------------------------
# Provider setup
# ---------------------------------------------------------------------------

PROVIDERS = {
    "anthropic": (
        "opentine.models.anthropic",
        "Anthropic",
        "claude-sonnet-5",
        "ANTHROPIC_API_KEY",
    ),
    "openai": ("opentine.models.openai", "OpenAI", "gpt-5.6", "OPENAI_API_KEY"),
    "google": (
        "opentine.models.google",
        "Google",
        "gemini-3.5-flash",
        "GOOGLE_API_KEY",
    ),
    "ollama": ("opentine.models.ollama", "Ollama", "llama3.1", None),
    "kimi": ("opentine.models.compat", "Kimi", "kimi-k3", "KIMI_API_KEY"),
    "deepseek": (
        "opentine.models.compat",
        "DeepSeek",
        "deepseek-v4-flash",
        "DEEPSEEK_API_KEY",
    ),
    "glm": ("opentine.models.compat", "GLM", "glm-5.2", "GLM_API_KEY"),
    "grok": ("opentine.models.compat", "Grok", "grok-4.5", "XAI_API_KEY"),
    "groq": (
        "opentine.models.compat",
        "Groq",
        "llama-3.3-70b-versatile",
        "GROQ_API_KEY",
    ),
    "together": (
        "opentine.models.compat",
        "Together",
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "TOGETHER_API_KEY",
    ),
    "mistral": (
        "opentine.models.compat",
        "Mistral",
        "mistral-large-2512",
        "MISTRAL_API_KEY",
    ),
    "ministral": (
        "opentine.models.compat",
        "Ministral",
        "ministral-14b-2512",
        "MISTRAL_API_KEY",
    ),
    "qwen": ("opentine.models.compat", "Qwen", "qwen3.7-max", "QWEN_API_KEY"),
    "openrouter": (
        "opentine.models.compat",
        "OpenRouter",
        "nousresearch/hermes-4-70b",
        "OPENROUTER_API_KEY",
    ),
    "hermes": ("opentine.models.compat", "Hermes", "Hermes-4-70B", "NOUS_API_KEY"),
    "lmstudio": ("opentine.models.compat", "LMStudio", "local-model", None),
    "unsloth": ("opentine.models.compat", "Unsloth", "default", None),
    "vllm": ("opentine.models.compat", "VLLM", "default", None),
    "llamacpp": ("opentine.models.compat", "LlamaCpp", "default", None),
    "localai": ("opentine.models.compat", "LocalAI", "default", None),
    "jan": ("opentine.models.compat", "Jan", "default", None),
}

LOCAL_OPENAI_COMPAT = {
    "lmstudio": (
        "LMSTUDIO_HOST",
        "LMSTUDIO_MODEL",
        "LMSTUDIO_API_KEY",
        "http://localhost:1234",
    ),
    "unsloth": ("UNSLOTH_HOST", "UNSLOTH_MODEL", "UNSLOTH_API_KEY", "http://localhost:8000"),
    "vllm": ("VLLM_HOST", "VLLM_MODEL", "VLLM_API_KEY", "http://localhost:8000"),
    "llamacpp": (
        "LLAMACPP_HOST",
        "LLAMACPP_MODEL",
        "LLAMACPP_API_KEY",
        "http://localhost:8080",
    ),
    "localai": ("LOCALAI_HOST", "LOCALAI_MODEL", "LOCALAI_API_KEY", "http://localhost:8080"),
    "jan": ("JAN_HOST", "JAN_MODEL", "JAN_API_KEY", "http://localhost:1337"),
}


#: Managed re-hosts. They are deliberately *not* in ``PROVIDERS``: their
#: credentials are a chain rather than one key, and the property under test is
#: usage-and-no-price, not the generic run/save/fork surface.
MANAGED_CLOUDS = ("bedrock", "vertex", "azure")


@pytest.fixture
def provider(request):
    name = request.config.getoption("--provider")
    if name in MANAGED_CLOUDS:
        pytest.skip(f"--provider {name} selects the managed-cloud smokes only")
    if name not in PROVIDERS:
        pytest.skip(f"Unknown provider: {name}. Choose from: {list(PROVIDERS.keys())}")
    return name


@pytest.fixture
def model(provider):
    module_path, class_name, default_model, env_key = PROVIDERS[provider]
    if env_key and not os.environ.get(env_key):
        pytest.skip(f"Set {env_key} env var to run live tests with {provider}")
    if provider == "ollama":
        _require_ollama_model(default_model)
    local_key = None
    if provider in LOCAL_OPENAI_COMPAT:
        host_env, model_env, key_env, default_host = LOCAL_OPENAI_COMPAT[provider]
        host = os.environ.get(host_env, default_host).rstrip("/")
        local_key = os.environ.get(key_env)
        available = _require_openai_compatible(provider, host, local_key)
        default_model = os.environ.get(model_env) or available[0]
    import importlib

    mod = importlib.import_module(module_path)
    adapter_cls = getattr(mod, class_name)
    if provider == "ollama":
        return adapter_cls(default_model, host=_ollama_host())
    if provider in LOCAL_OPENAI_COMPAT:
        return adapter_cls(default_model, host=host, api_key=local_key)
    return adapter_cls(default_model)


@pytest.fixture
def agent(model):
    return Agent(model=model, system="Answer concisely in one sentence.", max_steps=5)


def _ollama_host() -> str:
    return os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")


def _require_ollama_model(model_name: str) -> None:
    host = _ollama_host()
    try:
        with httpx.Client(timeout=5) as client:
            client.get(f"{host}/api/version").raise_for_status()
            tags = client.get(f"{host}/api/tags")
            tags.raise_for_status()
    except httpx.HTTPError as exc:
        pytest.skip(f"Ollama is not reachable at {host}: {exc}")

    installed = {
        item.get("model") or item.get("name")
        for item in tags.json().get("models", [])
        if item.get("model") or item.get("name")
    }
    if not any(name == model_name or name.startswith(f"{model_name}:") for name in installed):
        pytest.skip(f"Install Ollama model first: ollama pull {model_name}")


def _require_openai_compatible(provider: str, host: str, api_key: str | None) -> list[str]:
    base = host if host.rstrip("/").endswith("/v1") else f"{host.rstrip('/')}/v1"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        with httpx.Client(timeout=5, trust_env=False, follow_redirects=False) as client:
            response = client.get(f"{base}/models", headers=headers)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        pytest.skip(f"{provider} is not reachable at {host}: {exc}")
    models = [item.get("id") for item in response.json().get("data", []) if item.get("id")]
    if not models:
        pytest.skip(f"{provider} returned no model IDs from {base}/models")
    return models


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
        assert data["format_version"] == 2
        assert data["run_id"] == run.id
        assert len(data["graph"]["steps"]) == len(run.steps)


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


class TestLiveOllamaValidation:
    """Opt-in Ollama provider validation.

    Required setup:

      ollama pull qwen3
      ollama pull llama3.1
      uv run pytest tests/test_live.py -v --provider ollama
    """

    @pytest.mark.parametrize("model_name", OLLAMA_VALIDATION_MODELS)
    def test_ollama_completion_for_validation_models(self, provider, model_name, tmp_path):
        if provider != "ollama":
            pytest.skip("Ollama-only validation")
        _require_ollama_model(model_name)

        model = Ollama(
            model_name, host=_ollama_host(), think=True if model_name == "qwen3" else None
        )
        agent = Agent(model=model, system="Answer with only the final answer.", max_steps=4)
        run = agent.run_sync("What is 6 * 7?")

        assert run.status == RunStatus.completed
        assert run.model_info == f"ollama/{model_name}"
        assert run.steps[-1].kind == StepKind.done
        assert run.steps[-1].inputs.get("text")

        path = tmp_path / f"{model_name.replace(':', '_')}.tine"
        run.save(path)
        loaded = Run.load(path)
        assert loaded.model_info == run.model_info
        assert loaded.steps[-1].inputs == run.steps[-1].inputs

    def test_ollama_qwen3_tool_call_round_trip(self, provider):
        if provider != "ollama":
            pytest.skip("Ollama-only validation")
        _require_ollama_model("qwen3")

        def get_temperature(city: str) -> str:
            """Get the current temperature for a city."""
            return "22 C" if city else "unknown"

        model = Ollama("qwen3", host=_ollama_host(), think=True)
        agent = Agent(
            model=model,
            tools=[get_temperature],
            system=(
                "Use get_temperature when asked for a temperature. "
                "After receiving the tool result, answer in one short sentence."
            ),
            max_steps=6,
        )
        run = agent.run_sync("What is the temperature in Paris? Use the tool.")

        assert run.status == RunStatus.completed
        assert any(step.kind == StepKind.tool for step in run.steps)
        assert any(step.inputs.get("name") == "get_temperature" for step in run.steps)
        assert run.steps[-1].kind == StepKind.done

    def test_ollama_agent_replay_rerun_and_resume(self, provider):
        if provider != "ollama":
            pytest.skip("Ollama-only validation")
        _require_ollama_model("llama3.1")

        agent = Agent(
            model=Ollama("llama3.1", host=_ollama_host()),
            system="Answer concisely.",
            max_steps=4,
        )
        run = agent.run_sync("Name one primary color.")
        cached = agent.replay_sync(run, mode="cache")
        rerun = agent.replay_sync(run, mode="rerun")
        resumed = agent.resume_sync(run, prompt="Now name one different primary color.")

        assert cached.metadata["replay"]["mode"] == "cache"
        assert cached.metadata["replay"]["reused_steps"] == len(run.steps)
        assert rerun.status == RunStatus.completed
        assert resumed.status == RunStatus.completed
        assert resumed.metadata["forked_from"] == run.id


# ---------------------------------------------------------------------------
# Managed clouds — the merge gate for opentine.models.managed
# ---------------------------------------------------------------------------


def _managed_selected(request, cloud: str) -> None:
    """Skip unless this cloud was asked for by name.

    Double-guarding (``--provider`` *and* credentials) is deliberate: a machine
    that happens to have ambient AWS credentials should not start spending money
    because someone ran the offline suite.
    """
    selected = request.config.getoption("--provider")
    if selected != cloud:
        pytest.skip(f"managed-cloud smoke for {cloud}; run with --provider {cloud}")


def _require_env(*names: str) -> None:
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        pytest.skip(f"set {', '.join(missing)} to run this managed-cloud smoke")


def _require_any_env(*names: str) -> None:
    if not any(os.environ.get(name) for name in names):
        pytest.skip(f"set one of {', '.join(names)} to run this managed-cloud smoke")


def _assert_recorded_but_unpriced(result: dict, provider: str) -> None:
    """The whole managed-cloud thesis, checked against a real invoice-bearing call.

    Non-zero token counts are the load-bearing half: usage extraction is the one
    thing a re-host can break silently, because every other failure mode raises.
    A managed adapter that lost usage would look *identical* in the artifact to
    one working correctly — both report ``cost: 0.0`` — so only real counts from
    a real endpoint can tell them apart.
    """
    usage = result["usage"]
    assert usage["input"] > 0, f"{provider} reported no input tokens"
    assert usage["output"] > 0, f"{provider} reported no output tokens"
    assert usage["total"] > 0

    billing = result["billing"]
    calculation = billing["calculation"]
    assert calculation["provider"] == provider
    assert billing["status"] == "unknown"
    assert billing["amount_usd"] is None
    assert billing["rate_card_id"] is None
    assert result["cost"] == 0.0
    assert calculation["pricing_basis"] == MANAGED_UNPRICED
    print(f"\n  {provider}: usage={usage}, cost=unknown")


class TestLiveManagedClouds:
    """One real call per managed cloud. See this module's docstring to run them.

    Not in CI, and not runnable by accident: each test needs `--provider <cloud>`
    *and* that cloud's credentials, and skips cleanly without either.
    """

    async def test_bedrock_records_real_token_counts(self, request):
        _managed_selected(request, "bedrock")
        pytest.importorskip("anthropic", reason="pip install opentine[bedrock]")
        _require_any_env("AWS_REGION", "AWS_DEFAULT_REGION")
        _require_any_env(
            "AWS_BEARER_TOKEN_BEDROCK",
            "AWS_ACCESS_KEY_ID",
            "AWS_PROFILE",
            "AWS_ROLE_ARN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
        )
        from opentine.models.managed import Bedrock

        adapter = Bedrock(os.environ.get("BEDROCK_MODEL", "us.anthropic.claude-sonnet-5-v1:0"))
        result = await adapter.complete([{"role": "user", "content": "Reply with one word: ok"}])

        assert result["text"]
        _assert_recorded_but_unpriced(result, "bedrock")

    async def test_vertex_records_real_token_counts(self, request):
        _managed_selected(request, "vertex")
        pytest.importorskip("google.genai", reason="pip install opentine[vertex]")
        # Application Default Credentials cannot be probed from the environment;
        # run `gcloud auth application-default login` first.
        _require_env("GOOGLE_CLOUD_PROJECT")
        from opentine.models.managed import Vertex

        adapter = Vertex(os.environ.get("VERTEX_MODEL", "gemini-3.5-flash"))
        result = await adapter.complete([{"role": "user", "content": "Reply with one word: ok"}])

        assert result["text"]
        _assert_recorded_but_unpriced(result, "vertex")

    async def test_azure_openai_records_real_token_counts_streamed_and_not(self, request):
        """Azure gets the extra streamed leg, because that is where it fails silently.

        Azure's OpenAI-compatible endpoint sends a final usage chunk only when
        the request carries ``stream_options={"include_usage": True}``. Without
        it the stream simply ends: no error, no usage, zero tokens recorded, and
        a billing status of "unknown" that looks exactly like the intended
        managed-cloud silence. `AzureOpenAI` sets `include_usage=True` at the
        adapter level; this is the assertion that the real endpoint honours it.
        """
        _managed_selected(request, "azure")
        pytest.importorskip("openai", reason="pip install opentine[compat]")
        _require_any_env("AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_RESOURCE")
        _require_any_env("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_TOKEN")
        from opentine.models.managed import AzureOpenAI

        adapter = AzureOpenAI(
            os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-5.6"),
            resource=os.environ.get("AZURE_OPENAI_RESOURCE") or None,
            # An Entra bearer if the operator minted one; otherwise the adapter
            # reads AZURE_OPENAI_API_KEY and never OPENAI_API_KEY.
            api_key=os.environ.get("AZURE_OPENAI_TOKEN", ""),
        )
        prompt = [{"role": "user", "content": "Reply with one word: ok"}]

        result = await adapter.complete(prompt)
        assert result["text"]
        _assert_recorded_but_unpriced(result, "azure-openai")

        events = [event async for event in adapter.stream(prompt)]
        usage_events = [event for event in events if event["type"] == "usage"]
        assert len(usage_events) == 1, (
            "an Azure stream reported no usage chunk: stream_options was not honoured, "
            "so every streamed call would silently record zero tokens"
        )
        _assert_recorded_but_unpriced(usage_events[0], "azure-openai")
        assert any(event["type"] == "text_delta" for event in events)
