"""Universal research demo — works with ANY provider.

Searches the web for information about opentine and summarizes it.
Auto-detects whichever API key you have set, or asks you to pick.

Usage:
    # Set any one key, then run:
    uv run python examples/demo_research.py

    # PowerShell:
    $env:ANTHROPIC_API_KEY="sk-ant-..."
    uv run python examples/demo_research.py

    # Bash:
    export GROQ_API_KEY="gsk_..."
    python examples/demo_research.py
"""

import os
import sys

from opentine import Agent
from opentine.tools.search import search
from opentine.tools.web import fetch

# --- Auto-detect provider from env vars ---

DETECT_ORDER = [
    ("ANTHROPIC_API_KEY", "opentine.models.anthropic", "Anthropic", "claude-sonnet-4-20250514"),
    ("OPENAI_API_KEY", "opentine.models.openai", "OpenAI", "gpt-4o"),
    ("GOOGLE_API_KEY", "opentine.models.google", "Google", "gemini-2.0-flash"),
    ("GROQ_API_KEY", "opentine.models.compat", "Groq", "llama-3.1-70b-versatile"),
    ("DEEPSEEK_API_KEY", "opentine.models.compat", "DeepSeek", "deepseek-chat"),
    ("KIMI_API_KEY", "opentine.models.compat", "Kimi", "moonshot-v1-8k"),
    ("GLM_API_KEY", "opentine.models.compat", "GLM", "glm-4-flash"),
    (
        "TOGETHER_API_KEY",
        "opentine.models.compat",
        "Together",
        "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
    ),  # noqa: E501
    ("MISTRAL_API_KEY", "opentine.models.compat", "Mistral", "mistral-large-latest"),
    ("QWEN_API_KEY", "opentine.models.compat", "Qwen", "qwen-plus"),
]

model = None
for env_key, module_path, class_name, default_model in DETECT_ORDER:
    if os.environ.get(env_key):
        import importlib

        mod = importlib.import_module(module_path)
        adapter_cls = getattr(mod, class_name)
        model = adapter_cls(default_model)
        print(f"Detected {class_name} ({default_model}) via {env_key}")
        break

# Try Ollama as fallback (no key needed)
if model is None:
    try:
        import httpx

        r = httpx.get("http://localhost:11434/api/tags", timeout=2)
        if r.status_code == 200:
            from opentine.models.ollama import Ollama

            model = Ollama("llama3.1")
            print("Detected Ollama (local)")
    except Exception:
        pass

if model is None:
    print("No API key found. Set one of:")
    for env_key, _, name, _ in DETECT_ORDER:
        print(f"  {env_key}  ({name})")
    print("\nOr start Ollama: ollama serve")
    sys.exit(1)

# --- Run the research agent ---

agent = Agent(
    model=model,
    tools=[search, fetch],
    system=(
        "You are a research assistant. Use the search tool to find information, "
        "then use fetch to read relevant pages. Summarize your findings concisely."
    ),
    max_steps=8,
)

print("\nResearching: What is opentine?\n")

run = agent.run_sync(
    "What is opentine? Search the web and give me a concise summary "
    "of what it does and why developers would use it."
)
run.save("demo_research.tine")

# --- Display results ---

print("=== Run Tree ===\n")
for i, step in enumerate(run.steps):
    kind = step.kind.value
    text = step.inputs.get("text", "")
    name = step.inputs.get("name", "")
    args = step.inputs.get("arguments", {})

    if kind == "tool":
        arg_preview = ", ".join(f"{k}={repr(v)[:30]}" for k, v in args.items())
        print(f"  {i}. [{kind}]  {name}({arg_preview})")
    elif text:
        print(f"  {i}. [{kind}]  {text[:100]}")

print("\n=== Summary ===")
print(f"  Model:  {run.model_info}")
print(f"  Steps:  {len(run.steps)}")
print(f"  Cost:   ${run.total_cost:.4f}")
print(f"  Status: {run.status.value}")
print("  Saved:  demo_research.tine")
print("\nInspect:  tine show demo_research.tine")
print("Fork:     tine fork demo_research.tine --from-step 2")
