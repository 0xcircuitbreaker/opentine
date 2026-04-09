# opentine Unified Audit Report

**Date:** 2026-04-09
**Version:** 0.1.0
**Methodology:** Boris Cherny's parallel specialized agent workflow
**Audit Teams:** 6 independent agents, each focused on one concern
**Scope:** Full codebase at `C:/Users/Atlas/Documents/Github/opentine/`

---

## Executive Summary

| Audit Team | Score | Critical | High | Medium | Low |
|---|---|---|---|---|---|
| 1. Core Architecture | 6.5/10 | 1 | 4 | 10 | 9 |
| 2. Security | -- | 3 | 5 | 7 | 5 |
| 3. Model Adapters | 5.8/10 | 0 | 0 | 0 | 0 |
| 4. CLI & UX | 5.5/10 | 0 | 3 | 9 | 12 |
| 5. Test Coverage | ~11% | 2 | 4 | 4 | 0 |
| 6. Packaging | 64% ready | 0 | 2 | 4 | 7 |
| **TOTAL** | | **6** | **18** | **34** | **33** |

**Overall Assessment: The core design is elegant and the codebase is impressively compact, but opentine has fundamental issues that would prevent real-world use.** The tool-use round-trip is broken across all model adapters, security vulnerabilities exist in all tool modules, test coverage is ~11%, and the CLI has rendering bugs that contradict the README.

---

## CRITICAL Findings (6)

### C1. Tool-Use Round-Trip is Fundamentally Broken
**Source:** Architecture Audit, Model Adapter Audit
**Files:** `core.py:253-261`, all model adapters
**Impact:** Agent tool calling will fail with API errors for Anthropic, OpenAI, and Google

The Agent runtime does not propagate `tool_call_id` / `tool_use_id` from model responses into tool result messages. It sends `{"role": "tool", "content": result_str, "name": tname}` without the provider-specific ID. Additionally, the assistant message containing `tool_use` / `tool_calls` blocks is never appended to the conversation — only the text content is. Both Anthropic and OpenAI APIs require these for multi-turn tool conversations. **This means any agent workflow involving tool calls will fail.**

### C2. Unrestricted Shell Execution with Bypassable Allowlist
**Source:** Security Audit
**File:** `tools/shell.py:8-33`
**Impact:** Full host compromise

`shell=True` with a first-token allowlist check that is trivially bypassable via `;`, `&&`, `|`, `$()`, backticks. The subprocess inherits all env vars (including API keys), filesystem, and network access. An agent (or prompt injection via tool output) can execute arbitrary OS commands.

### C3. Arbitrary Python Code Execution Without Isolation
**Source:** Security Audit
**File:** `tools/python.py:11-32`
**Impact:** Full host compromise

Despite the docstring claiming "real isolation," the subprocess runs with the same user, filesystem, network, and environment variables (including all API keys). No sandboxing exists.

### C4. Indirect Prompt Injection via Tool Outputs
**Source:** Security Audit
**File:** `core.py:253-261`
**Impact:** Full host compromise (via chaining with C2/C3)

Tool outputs (from web.fetch, search, etc.) are passed directly into the conversation as tool messages. If a fetched page contains adversarial instructions, the model may follow them, leading to shell execution or API key exfiltration. This is the primary attack vector that chains all other vulnerabilities together.

### C5. OpenAI Adapter Fails on Tool Result Messages
**Source:** Architecture Audit
**File:** `models/openai.py:64-69`
**Impact:** Complete OpenAI tool-use failure

The OpenAI adapter uses `m.get("name", "")` as `tool_call_id`, which won't match the ID from the assistant's `tool_calls` response. OpenAI's API will return 400 errors on every tool-result round-trip.

### C6. Tool Results Not Stored in Step Outputs
**Source:** Architecture Audit
**File:** `core.py:253-261`
**Impact:** Defeats core value proposition

When a tool is called, the result is appended to `messages` but never stored in the step's `outputs` dict. The run tree captures *what was called* but not *what was returned*. For replay and debugging — the core value proposition — this is a fundamental omission. The `outputs` field on Step exists but is always empty for tool steps.

---

## HIGH Findings (18)

### H1. Duplicate Run IDs Cause Silent Overwrites
**Source:** Architecture Audit
**File:** `core.py:224`, `cli.py:124`

Two runs with the same prompt generate the same deterministic run ID. The CLI saves to `{run.id}.tine`, silently overwriting previous runs. For "git for agent runs," this is a significant gap.

### H2. The "Tree" is Actually a Linear Chain
**Source:** Architecture Audit
**File:** `core.py:65-87`

`add_step()` defaults to chaining each step to the previous one. There is no API to branch within a single run. The data structure supports trees but the runtime produces chains.

### H3. Unrestricted SSRF via web.fetch()
**Source:** Security Audit
**File:** `tools/web.py:12-37`

No URL validation. An agent can access cloud metadata endpoints (169.254.169.254), scan internal networks, or hit localhost services. `follow_redirects=True` bypasses any future URL filtering.

### H4. API Keys Accessible to Agent-Executed Code
**Source:** Security Audit
**Files:** All model adapters, `tools/python.py`, `tools/shell.py`

All API keys from environment variables are inherited by `python.execute()` and `shell.run()` subprocesses. Agent-generated code can trivially exfiltrate them.

### H5. Filesystem Sandbox `startswith` Bypass
**Source:** Security Audit, Architecture Audit
**File:** `tools/fs.py:9-15`

`str(resolved).startswith(str(base))` can be bypassed: a path resolving to `/home/user/project_evil/` passes the check for base `/home/user/project`. On Windows, case differences (`C:\` vs `c:\`) can also bypass it.

### H6. Agent Can Manipulate Its Own Run Tree
**Source:** Security Audit
**File:** `core.py:200-268`

The agent's tools have full filesystem access, so it can overwrite its own `.tine` file, read other runs' histories, or modify files that affect subsequent operations.

### H7. CLI `tine run` Has No Exception Handling
**Source:** CLI Audit
**File:** `cli.py:106`

`spec.loader.exec_module(mod)` has no try/except. Script errors dump raw Python tracebacks with no branded error message. This is the most common failure mode.

### H8. Zero Error Handling in All Model Adapters
**Source:** Model Adapter Audit
**Files:** All model adapters

No try/except, no retry logic, no handling of rate limits (429), auth errors, or timeouts in any adapter. A single transient network error crashes the entire run with an unhandled exception.

### H9. Streaming is Text-Only Across All Adapters
**Source:** Model Adapter Audit
**Files:** All model adapters

Tool calls, thinking blocks, usage data, and stop reasons are invisible during streaming. Google and Ollama don't even pass tool definitions in stream requests. Streaming is unusable for agentic workflows.

### H10. `supports_thinking` Declared but Never Activated
**Source:** Model Adapter Audit
**Files:** All model adapters

All adapters expose the property but none actually enable thinking/reasoning in API calls (Anthropic's `thinking` parameter, OpenAI's `reasoning_effort`, etc.). The property is decorative.

### H11. No Tests for Security-Critical fs.py Sandbox
**Source:** Test Coverage Audit
**File:** `tools/fs.py`

The path traversal sandbox (`_resolve()`) has zero tests. This is a security boundary with known bypass vectors and no coverage.

### H12. No Tests for shell.py Allowlist
**Source:** Test Coverage Audit
**File:** `tools/shell.py`

The allowlist check (`command.split()[0]`) is trivially bypassable and has zero tests.

### H13. No Tests for Any Model Adapter
**Source:** Test Coverage Audit
**Files:** `models/*.py`

All four adapters have complex message conversion, tool schema translation, and response parsing with zero test coverage. These are testable with mocked SDK clients.

### H14. `tine run` Can't Handle Async Scripts
**Source:** CLI Audit
**File:** `cli.py:109-115`

The CLI scans `dir(mod)` for `isinstance(obj, Run)`, but `agent.run()` returns a coroutine, not a Run. Only `agent.run_sync()` works. This is undocumented and the README quickstart uses the broken `agent.run()` form.

### H15. README Quickstart is Broken
**Source:** CLI Audit
**File:** `README.md`

The quickstart uses `run = agent.run("...")` which returns a coroutine, not a Run. Should be `agent.run_sync()`. The README also shows Unicode icons the CLI cannot produce, a duration field the code doesn't render, and `--from N` instead of the actual `--from-step N`.

### H16. Cost Tracking is Incomplete and Misleading
**Source:** Model Adapter Audit

Anthropic/OpenAI have single hardcoded price points ignoring model tiers, cached tokens, and thinking tokens. Google returns 0.0. Costs will be silently wrong when switching between models.

### H17. No PyPI Publish Workflow
**Source:** Packaging Audit
**File:** `.github/workflows/ci.yml`

CI only tests. No workflow for building wheels or publishing to PyPI. No trusted publisher setup. Blocks automated releases.

### H18. `<5 MB` Install Claim is Inaccurate
**Source:** Packaging Audit
**File:** `README.md`

Rich alone (with pygments) is ~5-6 MB. With httpx's dependency tree, the realistic core install is ~8-9 MB. The README comparison table claims <5 MB.

---

## MEDIUM Findings (34)

| # | Finding | Source | File |
|---|---|---|---|
| M1 | Hash truncation to 12 hex chars (48 bits) — collision risk at ~16M steps | Architecture | `core.py:39-42` |
| M2 | No protection against duplicate step IDs in a run | Architecture | `core.py:65-87` |
| M3 | No validation on `from_step_id` in `fork()` — empty runs silently created | Architecture | `core.py:115-127` |
| M4 | `dict[str, Any]` in inputs/outputs — unserialized types fail at save time only | Architecture | `core.py:31-32` |
| M5 | No schema versioning in serialized `.tine` format | Architecture | `core.py:55-63` |
| M6 | Large runs (10k+) — O(n^2) ancestors(), single-blob serialization | Architecture | `core.py` |
| M7 | Multiple tool calls create broken parent chain (siblings become chain) | Architecture | `core.py:253-261` |
| M8 | `run_sync()` fails inside existing event loops (Jupyter, async frameworks) | Architecture | `core.py:267-268` |
| M9 | No error handling contract in Model Protocol | Architecture | `core.py:152-174` |
| M10 | Protocol lacks `max_tokens` / `max_output_tokens` parameter | Architecture | `core.py:152-174` |
| M11 | Tavily API key sent in request body (logged by proxies) | Security | `tools/search.py:26-28` |
| M12 | API keys stored as plain instance attributes | Security | All model adapters |
| M13 | No `.tine` file integrity verification (no HMAC/signature) | Security | `core.py:134-136` |
| M14 | System prompt exposed in `.tine` files | Security | `core.py:60` |
| M15 | Error messages leak internal state to model | Security | `core.py:259` |
| M16 | No tool output size limits | Security | `core.py:257` |
| M17 | Ollama host SSRF via configurable `OLLAMA_HOST` | Security | `models/ollama.py:17` |
| M18 | Google adapter: `resp.text` can raise if response has only function calls | Model Adapters | `models/google.py` |
| M19 | Google adapter: tools not passed in streaming request | Model Adapters | `models/google.py` |
| M20 | Google adapter: tool results sent as plain text, not function_response | Model Adapters | `models/google.py` |
| M21 | OpenAI: `temperature=0.0` causes API error for o-series models | Model Adapters | `models/openai.py` |
| M22 | Ollama: `supports_tools=True` unconditionally (not all models support it) | Model Adapters | `models/ollama.py` |
| M23 | Ollama: new httpx client per request (no connection reuse) | Model Adapters | `models/ollama.py` |
| M24 | CLI `str(label)` bug strips all icon colors from tree rendering | CLI | `cli.py:158` |
| M25 | No handling for corrupt `.tine` files in show/fork/replay/diff/resume | CLI | `cli.py` |
| M26 | `_find_run` creates `.tine_runs` dir as side effect on read operations | CLI | `cli.py` |
| M27 | `tine diff` uses naive positional comparison, no alignment algorithm | CLI | `cli.py` |
| M28 | `tine fork --save` silently overwrites existing files | CLI | `cli.py` |
| M29 | Blaze Orange on light terminals is low contrast | CLI | `cli.py` |
| M30 | `force_terminal=True` produces ANSI codes when piping to files | CLI | `cli.py:37` |
| M31 | No dev/test dependency group in pyproject.toml | Packaging | `pyproject.toml` |
| M32 | `[ollama]` extra installs unused package (adapter uses httpx directly) | Packaging | `pyproject.toml`, `models/ollama.py` |
| M33 | Mermaid diagrams won't render on PyPI page | Packaging | `README.md` |
| M34 | fs.py startswith check: Windows case sensitivity issue | Packaging | `tools/fs.py:14` |

---

## Test Coverage Summary

**Estimated Overall Coverage: ~11%**

| Module | Lines | Coverage |
|---|---|---|
| `core.py` | 269 | ~56% |
| `cli.py` | 362 | 0% |
| `models/anthropic.py` | 124 | 0% |
| `models/openai.py` | 142 | 0% |
| `models/google.py` | 131 | 0% |
| `models/ollama.py` | 112 | 0% |
| `tools/fs.py` | 50 | 0% |
| `tools/shell.py` | 34 | 0% |
| `tools/python.py` | 33 | 0% |
| `tools/search.py` | 90 | 0% |
| `tools/web.py` | 38 | 0% |
| **TOTAL** | **~1,385** | **~11%** |

---

## Model Adapter Parity Matrix

| Feature | Anthropic | OpenAI | Google | Ollama |
|---|---|---|---|---|
| Basic completion | Yes | Yes | Yes | Yes |
| Basic streaming | Yes | Yes | Yes | Yes |
| Tool definitions | Yes | Yes | Yes | Yes |
| Tool call parsing | Yes | Yes | Yes | Yes |
| Tool result format | BROKEN | BROKEN | BROKEN | Partial |
| Streaming tool calls | No | No | No | No |
| Cost tracking | Partial | Partial | None | N/A |
| Error handling | None | None | None | Minimal |
| max_tokens config | Hardcoded | None | None | None |
| Thinking activation | No | No | No | N/A |

---

## PyPI Readiness

**Score: 64% — NOT READY**

**Pass:** 18/28 checks
**Fail:** 8/28 (no publish workflow, test deps not declared, install size claim inaccurate, unused ollama dep, no `__main__.py`, Mermaid won't render, `[all]` extras copy-pasted, no trusted publisher)
**Unknown:** 2/28 (PyPI name availability, test passing confirmation)

---

## Priority Ranking: Top 10 Actions

| # | Action | Severity | Effort | Impact |
|---|---|---|---|---|
| 1 | Fix tool_call_id/tool_use_id threading in Agent runtime | CRITICAL | Medium | Unblocks all tool-use functionality |
| 2 | Store tool results in step outputs | CRITICAL | Low | Enables replay/diff of what actually happened |
| 3 | Fix assistant message propagation (include tool_calls blocks) | CRITICAL | Medium | Required for multi-turn tool conversations |
| 4 | Add sandbox to shell.py (shell=False, proper allowlist) | CRITICAL | Medium | Prevents host compromise |
| 5 | Add isolation to python.py (clear env vars at minimum) | CRITICAL | Low | Prevents API key exfiltration |
| 6 | Fix `_resolve()` sandbox (use `relative_to()` not `startswith`) | HIGH | Low | Prevents path traversal |
| 7 | Add URL validation to web.fetch (block private IPs) | HIGH | Low | Prevents SSRF |
| 8 | Fix CLI `str(label)` rendering bug | MEDIUM | Low | Icons render in color as designed |
| 9 | Fix README to match actual CLI output | MEDIUM | Low | Prevents user confusion |
| 10 | Add model adapter tests with mocked SDK clients | HIGH | Medium | Catches message conversion bugs |

---

## Methodology Notes

This audit followed Boris Cherny's (creator of Claude Code) workflow patterns:

- **6 parallel specialized agents** — each focused on a single concern with no overlap
- **Verification-first** — each agent read actual source code with line numbers, no assumptions
- **Grilling, not accepting** — agents challenged every design decision
- **Assessment only** — no fixes applied, findings documented for prioritized remediation
- **Structured findings** — severity-rated, actionable, with exact file:line references

Sources:
- [howborisusesclaudecode.com](https://howborisusesclaudecode.com)
- [Boris Cherny on X](https://x.com/bcherny/status/2007179832300581177)

---

*Generated by 6 parallel audit agents on 2026-04-09*
