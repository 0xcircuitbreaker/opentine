# opentine

Local-first provenance for agent runs: record model/tool steps as a portable `.tine` artifact, fork from a step, replay cached outputs, rerun through an explicit harness, and diff graph history.


The public primitive layer in `opentine/core.py` is intentionally small: currently 52 physical lines. Heavier graph, runtime, cache, and policy logic lives in focused modules.

## Install

```bash
pip install opentine
```

The opentine package itself is small. Core runtime dependencies install normally, and optional provider SDKs such as Anthropic, OpenAI, and Google packages are selected through dependency extras.

## Quickstart

```python
from opentine import Agent
from opentine.models.anthropic import Anthropic

agent = Agent(model=Anthropic("claude-sonnet-4-20250514"))
run = agent.run_sync("What is opentine?")
run.save("result.tine")
```

```bash
tine show result.tine
tine verify result.tine
tine fork result.tine --from-step 0 --save forked.tine
tine replay result.tine --mode cache --save replayed.tine
tine replay result.tine --inspect
tine diff result.tine forked.tine
```

`tine replay` is no longer a synonym for printing saved steps. Use `--inspect` or `--dry-run` to view recorded events without creating a replay artifact.

## Testing

Fast local gates validate Opentine runtime behavior with mocks and local fixtures:

```bash
pytest tests -m "not live and not live_harness"
ruff check .
ruff format --check .
```

### 0.1.x Full-Release Readiness Evidence

The current release-readiness pass keeps package metadata at `Development Status :: 4 - Beta` while validating the 0.1.x surface that is actually claimed. The fast suite confirms `.tine` save/load, integrity verification, golden v1 fixture behavior, graph refs, fork, diff, cached replay, native rerun/resume with mocks, CLI show/verify/fork/replay/diff, CLI failure paths, harness parsing, secure defaults, provider adapter payload shape for Ollama, OpenAI/OpenAI-compatible, Anthropic, and Google, and a CI-sized graph performance smoke.

Latest local audit results:

- `ruff check .`: passing
- `ruff format --check .`: passing
- `pytest tests -m "not live and not live_harness" -q`: 68 passed, 12 deselected
- `pytest tests -m "not live_harness" -q`: 68 passed, 11 skipped, 1 deselected
- Focused integrity/golden/performance/CLI suite: 50 passed

Current live validation for this audit environment:

- `pytest tests/test_live.py --provider ollama -q`: 11 passed with local `llama3.1` and `qwen3`
- `pytest tests/test_live_harness.py -m live_harness --agent-harness codex -q`: 1 passed
- `pytest tests/test_live_harness.py -m live_harness --agent-harness kimi-code -q`: 1 passed
- `pytest tests/test_live.py --provider lmstudio -q -rs`: 11 skipped because `http://localhost:1234` was not reachable
- Package build: `opentine-0.1.0.tar.gz` and `opentine-0.1.0-py3-none-any.whl` built; Twine metadata check passed; clean wheel install, import, `tine --help`, `tine verify`, beta classifier, and `pip check` verified



### Testing Your Agent CLI

Harness compatibility tests are separate from live model/provider tests. They run real external CLIs in disposable temp repos and skip when the CLI is not installed or not authenticated:

```bash
pytest tests/test_live_harness.py -m live_harness --agent-harness codex
pytest tests/test_live_harness.py -m live_harness --agent-harness opencode
pytest tests/test_live_harness.py -m live_harness --agent-harness kimi-code
pytest tests/test_live_harness.py -m live_harness --agent-harness openclaw
pytest tests/test_live_harness.py -m live_harness --agent-harness hermes
```

The default profiles are:

- `codex`: `codex exec <task>`
- `claude-code`: `claude -p <task>`
- `opencode`: `opencode run <task>`
- `kimi-code`: `kimi --print --output-format stream-json --prompt <task>` after `kimi login`
- `openclaw`: `openclaw agent --local --json --message <task>`
- `hermes`: `hermes chat -q <task>`
- `generic` and `pi`: user-supplied command

Every profile is overrideable:

```bash
tine run --harness generic --harness-command "your-agent run" --prompt "Inspect this repo"
pytest tests/test_live_harness.py -m live_harness --agent-harness generic --harness-command "your-agent run"
```

Harness subprocesses are isolated by default. For logged-in CLIs, pass `--harness-login-env` to allow only `PATH`, home/config directory variables, and tool-specific config directory variables; opentine does not write pasted secrets to repo files.

### Native Runtime Validation

Live native model/runtime behavior is opt-in. The Ollama validation profile uses `llama3.1` for default-model compatibility and `qwen3` for tool-calling/thinking coverage:

```bash
ollama pull llama3.1
ollama pull qwen3
pytest tests/test_live.py -v --provider ollama
```

The live suite checks Ollama health at `http://localhost:11434`, basic completion for both models, `qwen3` tool-call round trips, `.tine` save/load, fork, cached replay, rerun replay, resume, and local CLI graph operations. Ollama, GLM, LM Studio, Unsloth-compatible endpoints, vLLM, llama.cpp, LocalAI, Jan, and other OpenAI-compatible local runtimes validate opentine's native `Agent` protocol or the model runtime underneath a harness; they are not the main external agent integration surface. To test an agent that uses Ollama, run that agent through the harness layer and configure the agent itself to use Ollama.

## `.tine` Contract

Top-level fields:

`format_version`, `run_id`, `created_at`, `status`, `graph`, `refs`, `transcript`, `manifest`, `policies`, `cache`, `metadata`.

The graph is content-addressed. Step IDs are full SHA-256 hashes over an immutable canonical payload including parent links, kind, inputs, outputs, model/tool metadata, and errors. CLI output displays short IDs for readability.

`Run.steps` remains as a stable traversal view for compatibility, but the stored artifact is a DAG with `parent_ids`, branch/tip refs, common-ancestor lookup, and graph-aware diff.

Saved artifacts include `metadata.integrity` with a SHA-256 checksum. Use `Run.verify_integrity(path_or_data)` or `tine verify <run.tine>` to check it. This is an integrity checksum, not tamper-proof signing; HMAC/signature support is future work.

The current compatibility promise is `format_version == 1` only. Future or missing format versions are rejected clearly, and migration support is future work. See [TINE_FORMAT.md](TINE_FORMAT.md).

## Replay And Resume Scope

opentine-native `Agent` runs get:

- full event recording
- cached replay using recorded outputs
- rerun replay through the model/tool runtime
- resume from saved provider-neutral transcript/tool state

External harnesses get:

- event recording
- fork context
- cached replay of recorded outputs
- rerun by invoking the harness again
- command metadata, harness name, and model/session metadata when available
- best-effort resume only when the external tool exposes session support and the adapter explicitly declares it

If a run manifest does not declare resume support, `tine resume` fails with a precise explanation instead of pretending that loading a file continued the agent.

Support levels:

- `Structured`: CLI emits JSON/JSONL, which gives the best step fidelity.
- `Text`: CLI emits plain output, so opentine records line-level events with simple heuristics.
- `Session-aware`: harness can record session IDs and command metadata; true resume depends on the external tool.
- `Native Agent`: opentine directly controls the model/tool loop.

## Security Defaults

The built-in policy profiles are explicit:

- `secure_profile()` is the baseline.
- `dev_profile()` opens common local development affordances.
- `isolated_profile()` is stricter for tamper-sensitive workflows.

Tool defaults are conservative:

- Filesystem access uses `Path.relative_to`, sandbox roots, optional symlink denial, max file sizes, and write allowlists.
- Network fetch blocks private, link-local, loopback, reserved, and multicast hosts by default and re-checks redirects.
- Shell execution is disabled unless a `ShellPolicy` enables it; commands are parsed to arrays, env inheritance is off by default, and output is capped.
- Python execution is disabled unless a `PythonPolicy` enables it; subprocess env is scrubbed by default and output is capped.
- Harness subprocesses do not inherit the parent environment by default.


## Comparison

Git stores content-addressed DAGs for source history. opentine stores a content-addressed DAG for agent execution provenance: model calls, tool calls, outputs, errors, cache provenance, and transcript state.

GitHub Copilot and Codex provide hosted/cloud or CLI workflows around tasks, worktrees, sandboxes, logs, and review flows. opentine is a portable local artifact and replay layer that can wrap external harnesses but does not replace their hosted workflow features. GitHub documents Copilot session logs and tool traces, plus a cloud-agent firewall with documented limitations. OpenAI’s Codex docs expose product areas for app, CLI, worktrees, sandboxing, and security.

GitHub Models focuses on prompt development, model comparison, evaluators, and prompt configs in repositories. opentine focuses on tool-using execution traces and replayable run provenance.

Hugging Face Hub repositories are Git repositories optimized for models, datasets, Spaces, and large AI/ML artifacts. opentine `.tine` files can be hosted there or in Git, but the artifact format is specifically for agent run provenance.

LangGraph is the closest technical comparison for checkpoint replay and time travel, but it is framework/checkpointer-oriented rather than a standalone `.tine` artifact. LangSmith and CrewAI tracing are stronger observability/evaluation surfaces; opentine is a local provenance artifact and graph-operation layer.

Sources:

- Ollama chat API: https://docs.ollama.com/api/chat
- Ollama pull API: https://docs.ollama.com/api/pull
- Ollama tool calling: https://docs.ollama.com/capabilities/tool-calling
- Ollama thinking: https://docs.ollama.com/capabilities/thinking
- OpenCode CLI: https://opencode.ai/docs/cli/
- Kimi Code CLI: https://www.kimi.com/code/docs/en/kimi-code-cli/reference/kimi-command.html
- OpenClaw agent CLI: https://docs.openclaw.ai/cli/agent
- Hermes Agent CLI: https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/cli.md
- GitHub Copilot session logs: https://docs.github.com/en/copilot/how-tos/use-copilot-agents/cloud-agent/track-copilot-sessions
- GitHub Copilot cloud-agent firewall: https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/customize-the-agent-firewall
- GitHub Models: https://docs.github.com/en/github-models/about-github-models
- Hugging Face Hub repositories: https://huggingface.co/docs/hub/en/repositories
- LangGraph persistence/time travel: https://docs.langchain.com/oss/python/langgraph/persistence
- LangSmith evaluations: https://docs.langchain.com/langsmith/evaluation
- CrewAI observability/tracing: https://docs.crewai.com/en/observability
- OpenAI Codex docs: https://developers.openai.com/codex/cloud
