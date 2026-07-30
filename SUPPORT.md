# Support Policy

OpenTine is an unfunded beta project. There is no support SLA, no guaranteed
response time, and no paid support channel. Issues are triaged when a
maintainer has time.

## Where to Ask

- Bugs and feature requests:
  [GitHub Issues](https://github.com/0xcircuitbreaker/opentine/issues). Include
  the OpenTine version or commit, Python version, operating system, and a
  minimal reproduction.
- Usage questions: also GitHub Issues. GitHub Discussions is not enabled on
  this repository.
- Security vulnerabilities: do not open an issue. Follow
  [SECURITY.md](SECURITY.md).

Supported Python versions are listed in `README.md`. `.tine` portable-format
and repository-object compatibility is specified in
[TINE_FORMAT.md](docs/TINE_FORMAT.md).

## Integration Support Levels

- `Validated`: a repeatable gate passed for the current beta.
- `Scoped`: adapter or compatibility code exists, but live behavior depends on user environment or provider configuration.
- `Skipped`: a gate was attempted but prerequisite services were unavailable.
- `Unavailable`: the target was not installed, authenticated, or otherwise runnable for the validation gate.

## Model Adapter Scope

- `Validated`: wire-shape, usage, billing, refusal/reasoning, tool continuation,
  and resource-bound fixtures for native OpenAI, Anthropic, Google, and Ollama.
- `Validated` contracts, `Scoped` live services: Kimi/Moonshot, DeepSeek,
  GLM/Z.AI, xAI/Grok, Groq, Qwen, Together, Mistral/Ministral, OpenRouter, and
  direct Nous/Hermes through provider-scoped Chat Completions adapters.
- `Scoped`: LM Studio, vLLM, Unsloth, llama.cpp/llama-cpp-python, LocalAI, Jan,
  SGLang, TGI, MLX-LM, NVIDIA NIM, TensorRT-LLM, KoboldCpp, LiteLLM, and other
  OpenAI-compatible local runtimes through exact-base generic transport. Model
  discovery, chat templates, tools, reasoning, and usage fields depend on the
  configured server and loaded model.

An exact signed price card is independent of transport support. Unknown models
remain runnable but visibly unpriced. Local runtime adapters default to
`unmetered` unless per-token rates are supplied for infrastructure accounting.
The `LiteLLM` preset and the generic `OpenAICompatible` transport are the
exceptions: both default to metered because a gateway may route paid hosted
APIs, so without an exact rate card their billing status is `unknown`, not
`unmetered`.
