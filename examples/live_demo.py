"""Interactive live demo — pick a provider, enter a key, see opentine in action.

Usage:
    python examples/live_demo.py
"""

import importlib
import os
import sys

from opentine import Agent

PROVIDERS = {
    # Cloud providers
    "1": ("Kimi (Moonshot)", "opentine.models.compat", "Kimi", "kimi-k2.6", "KIMI_API_KEY"),
    "2": ("OpenAI", "opentine.models.openai", "OpenAI", "gpt-5.6", "OPENAI_API_KEY"),
    "3": (
        "Anthropic",
        "opentine.models.anthropic",
        "Anthropic",
        "claude-sonnet-5",
        "ANTHROPIC_API_KEY",
    ),  # noqa: E501
    "4": (
        "DeepSeek",
        "opentine.models.compat",
        "DeepSeek",
        "deepseek-v4-flash",
        "DEEPSEEK_API_KEY",
    ),
    "5": ("Qwen", "opentine.models.compat", "Qwen", "qwen3.7-max", "QWEN_API_KEY"),
    "6": ("GLM / Z.AI", "opentine.models.compat", "GLM", "glm-5.1", "GLM_API_KEY"),
    "7": ("Grok / xAI", "opentine.models.compat", "Grok", "grok-4.5", "XAI_API_KEY"),
    "8": (
        "Together",
        "opentine.models.compat",
        "Together",
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "TOGETHER_API_KEY",
    ),  # noqa: E501
    "9": (
        "Ministral",
        "opentine.models.compat",
        "Ministral",
        "ministral-3-14b",
        "MISTRAL_API_KEY",
    ),  # noqa: E501
    # Local providers (no API key needed)
    "10": ("Ollama (local)", "opentine.models.ollama", "Ollama", "llama3.1", None),
    "11": ("LM Studio (local)", "opentine.models.compat", "LMStudio", "local-model", None),
    "12": ("vLLM (local)", "opentine.models.compat", "VLLM", "default", None),
    "13": ("llama.cpp (local)", "opentine.models.compat", "LlamaCpp", "default", None),
    "14": ("LocalAI (local)", "opentine.models.compat", "LocalAI", "default", None),
    "15": ("Jan (local)", "opentine.models.compat", "Jan", "default", None),
}

print("\n=== opentine live demo ===\n")
print("Cloud providers:")
for k, (name, *_) in PROVIDERS.items():
    if int(k) <= 9:
        print(f"  {k:>2}. {name}")
print("\nLocal providers (no API key needed):")
for k, (name, *_) in PROVIDERS.items():
    if int(k) >= 10:
        print(f"  {k:>2}. {name}")

choice = input("\nEnter number: ").strip()
if choice not in PROVIDERS:
    print("Invalid choice.")
    sys.exit(1)

name, module_path, class_name, default_model, env_key = PROVIDERS[choice]

# Get API key
if env_key:
    api_key = os.environ.get(env_key, "")
    if not api_key:
        api_key = input(f"Enter {env_key} (or set env var): ").strip()
        if not api_key:
            print("No API key provided.")
            sys.exit(1)
        os.environ[env_key] = api_key

# Import the adapter
mod = importlib.import_module(module_path)
adapter_cls = getattr(mod, class_name)

print(f"\nUsing {name} with model {default_model}...")
agent = Agent(
    model=adapter_cls(default_model),
    system="You are a helpful assistant. Be concise.",
)

prompt = input("\nEnter a prompt (or press Enter for default): ").strip()
if not prompt:
    prompt = "Explain what a 'tine' is and why it's a good name for a tool that forks agent runs."

print("\nRunning agent...\n")
run = agent.run_sync(prompt)
run.save("live_demo.tine")

# Display results
for step in run.steps:
    kind = step.kind.value
    text = step.inputs.get("text", "")
    tool_name = step.inputs.get("name", "")
    if text:
        preview = text[:120].replace("\n", " ")
        print(f"  [{kind}] {preview}")
    elif tool_name:
        print(f"  [{kind}] {tool_name}(...)")

print(f"\n  Steps: {len(run.steps)}")
print(f"  Cost:  ${run.total_cost:.4f}")
print("  Saved: live_demo.tine")
print("\nNow try:")
print("  tine show live_demo.tine")
print("  tine fork live_demo.tine --from-step 0")
