"""Cross-model comparison — run the same agent on different providers.

Usage:
    tine run examples/cross_model.py

Set the API keys for the providers you want to compare.
"""
import os

from opentine import Agent

prompt = "Explain the CAP theorem in distributed systems in exactly 3 sentences."

models = []

if os.environ.get("ANTHROPIC_API_KEY"):
    from opentine.models.anthropic import Anthropic
    models.append(("anthropic", Anthropic("claude-sonnet-4-20250514")))

if os.environ.get("OPENAI_API_KEY"):
    from opentine.models.openai import OpenAI
    models.append(("openai", OpenAI("gpt-4o")))

if os.environ.get("GOOGLE_API_KEY"):
    from opentine.models.google import Google
    models.append(("google", Google("gemini-2.0-flash")))

if os.environ.get("OLLAMA_HOST") or True:  # Ollama defaults to localhost
    try:
        from opentine.models.ollama import Ollama
        models.append(("ollama", Ollama("llama3.1")))
    except Exception:
        pass

if not models:
    print("Set at least one API key: ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY")
    exit(1)

for name, model in models:
    print(f"\n--- {name} ({model.name}) ---")
    try:
        agent = Agent(model=model)
        run = agent.run_sync(prompt)
        run.save(f"cross_{name}.tine")
        last_step = run.steps[-1] if run.steps else None
        if last_step:
            print(last_step.inputs.get("text", "")[:200])
        print(f"  Steps: {len(run.steps)}, Cost: ${run.total_cost:.4f}")
    except Exception as e:
        print(f"  Error: {e}")
