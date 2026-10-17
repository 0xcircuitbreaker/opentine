"""0.10 local runtimes: Ollama host/cloud/cache, presets, overrides, CLI flags."""

from __future__ import annotations

import argparse

import pytest

from opentine._local_providers import LOCAL_UNMETERED_PROVIDERS
from opentine.models import _local, resolve_model
from opentine.models._ollama_billing import ollama_meter
from opentine.models._ollama_host import normalize_host, served_by_cloud
from opentine.models._usage import ollama_usage


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, "http://localhost:11434"),
        ("0.0.0.0", "http://0.0.0.0:11434"),
        ("127.0.0.1:11434", "http://127.0.0.1:11434"),
        ("gpu-box", "http://gpu-box:11434"),
        ("[::1]", "http://[::1]:11434"),
        ("http://localhost", "http://localhost"),
        ("https://ollama.com/", "https://ollama.com"),
    ],
)
def test_ollama_host_takes_the_forms_ollama_documents(raw, expected):
    assert normalize_host(raw) == expected


def test_ollama_host_refuses_other_schemes():
    with pytest.raises(ValueError):
        normalize_host("file:///etc/passwd")


def test_ollama_adapter_reads_a_schemeless_host(monkeypatch):
    from opentine.models.ollama import Ollama

    monkeypatch.setenv("OLLAMA_HOST", "127.0.0.1:11500")
    assert Ollama("qwen3")._host == "http://127.0.0.1:11500"


def test_ollama_cached_prompt_count_is_a_cache_read_inside_input():
    usage = ollama_usage(
        {"prompt_eval_count": 100, "prompt_eval_cached_count": 70, "eval_count": 5}
    )
    assert (usage.input, usage.cache_read, usage.output) == (30, 70, 5)
    capped = ollama_usage({"prompt_eval_count": 10, "prompt_eval_cached_count": 99})
    assert (capped.input, capped.cache_read) == (0, 10)


@pytest.mark.parametrize(
    ("host", "model", "data"),
    [
        ("http://localhost:11434", "gpt-oss:120b-cloud", {}),
        ("http://localhost:11434", "gemma4:cloud", {}),
        ("http://localhost:11434", "qwen3", {"remote_model": "qwen3-max", "remote_host": "x"}),
        ("https://ollama.com", "qwen3", {}),
    ],
)
def test_ollama_cloud_is_never_recorded_as_free(host, model, data):
    assert served_by_cloud(host, model, data)
    metered = ollama_meter(
        model,
        {**data, "prompt_eval_count": 10, "eval_count": 2},
        None,
        None,
        False,
        cloud=served_by_cloud(host, model, data),
    )
    assert metered["provider"] == "ollama-cloud"
    assert metered["billing"]["status"] != "unmetered"


def test_local_ollama_stays_unmetered():
    assert not served_by_cloud("http://localhost:11434", "qwen3:8b", {})
    metered = ollama_meter("qwen3:8b", {"prompt_eval_count": 1, "eval_count": 1}, None, None, False)
    assert metered["billing"]["status"] == "unmetered"


def test_ollama_api_key_goes_only_to_ollama_cloud(monkeypatch):
    from opentine.models.ollama import Ollama

    monkeypatch.setenv("OLLAMA_API_KEY", "fake-ollama-key")
    assert "Authorization" not in Ollama("qwen3", host="http://localhost:11434")._headers
    cloud = Ollama("qwen3", host="https://ollama.com")
    assert cloud._headers["Authorization"] == "Bearer fake-ollama-key"


def test_the_unmetered_registry_is_the_preset_registry():
    """Capture and ``tine price`` must agree on which providers are free."""
    expected = (set(_local()) - {"litellm"}) | {"ollama", "local", "local-anthropic-compatible"}
    assert expected == set(LOCAL_UNMETERED_PROVIDERS)


@pytest.mark.parametrize("name", ["localai", "koboldcpp"])
def test_localai_and_koboldcpp_request_stream_usage(name):
    assert resolve_model(name)._include_usage is True


@pytest.mark.parametrize(
    ("name", "base"),
    [
        ("docker-model-runner", "http://localhost:12434/engines/v1"),
        ("lemonade", "http://localhost:13305/api/v1"),
        ("tabbyapi", "http://localhost:5000/v1"),
        ("xinference", "http://localhost:9997/v1"),
        ("lmdeploy", "http://localhost:23333/v1"),
        ("aphrodite", "http://localhost:2242/v1"),
    ],
)
def test_new_local_presets_point_at_their_runtime(name, base):
    adapter = resolve_model(f"{name}:m")
    assert (adapter._provider, adapter._base_url) == (name, base)


@pytest.mark.parametrize("name", ["foundry-local", "ovms"])
def test_presets_without_a_conventional_port_need_a_base_url(name, monkeypatch):
    with pytest.raises(ValueError, match="base_url"):
        resolve_model(name)
    env = name.upper().replace("-", "_")
    monkeypatch.setenv(f"{env}_BASE_URL", "http://127.0.0.1:5273/v1")
    assert resolve_model(name)._base_url == "http://127.0.0.1:5273/v1"


def test_per_preset_environment_overrides(monkeypatch):
    monkeypatch.setenv("LLAMACPP_BASE_URL", "http://127.0.0.1:9931/v1")
    monkeypatch.setenv("LLAMACPP_API_KEY", "real-secret-key")
    adapter = resolve_model("llamacpp")
    assert adapter._base_url == "http://127.0.0.1:9931/v1"
    assert adapter._api_key == "real-secret-key"


def test_a_real_key_from_the_environment_is_still_transport_checked(monkeypatch):
    monkeypatch.delenv("OPENTINE_ALLOW_INSECURE_ENDPOINTS", raising=False)
    monkeypatch.setenv("JAN_BASE_URL", "http://192.0.2.7:1337/v1")
    monkeypatch.setenv("JAN_API_KEY", "real-secret-key")
    with pytest.raises(ValueError, match="cleartext"):
        resolve_model("jan")


# --------------------------------------------------------------------------- #
# tine run --model --base-url / --api-key-env
# --------------------------------------------------------------------------- #


def test_build_model_points_a_preset_elsewhere_with_a_named_key(monkeypatch):
    from opentine._cli_run_model import build_model

    monkeypatch.setenv("MY_LOCAL_KEY", "fake-local-key")
    adapter = build_model("llamacpp:qwen", "http://127.0.0.1:9931/v1", "MY_LOCAL_KEY")
    assert adapter._base_url == "http://127.0.0.1:9931/v1"
    assert adapter._api_key == "fake-local-key"
    assert build_model("ollama:qwen3", "gpu-box", None)._host == "http://gpu-box:11434"
    anthropic = build_model("anthropic:claude-opus-5-5", "http://127.0.0.1:8080", None)
    assert anthropic._base_url == "http://127.0.0.1:8080"


def test_build_model_refuses_a_missing_key_variable_and_a_cleartext_override(monkeypatch):
    from opentine._cli_run_model import build_model

    monkeypatch.delenv("OPENTINE_ALLOW_INSECURE_ENDPOINTS", raising=False)
    monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
    with pytest.raises(ValueError, match="not set"):
        build_model("vllm", None, "NOT_SET_ANYWHERE")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-fake-deepseek")
    with pytest.raises(ValueError, match="cleartext"):
        build_model("deepseek", "http://192.0.2.9/v1", "DEEPSEEK_API_KEY")


def test_model_flags_are_refused_outside_a_model_run():
    from opentine._cli_run_model import refuse_model_flags

    args = argparse.Namespace(base_url="http://127.0.0.1:1/v1", api_key_env=None)
    with pytest.raises(SystemExit):
        refuse_model_flags(args, "without --model")
    refuse_model_flags(argparse.Namespace(base_url=None, api_key_env=None), "without --model")
