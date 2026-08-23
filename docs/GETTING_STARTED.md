# Getting started

From `pip install` to a verified, forked, promoted agent run. Every command on
this page exists in the shipped CLI; `tine <verb> --help` is authoritative if
this page ever drifts.

Contents:

1. [Install](#1-install)
2. [Your first captured run, with no code](#2-your-first-captured-run-with-no-code)
3. [Read the run](#3-read-the-run)
4. [Fork it, diff it, prove it reproduces](#4-fork-it-diff-it-prove-it-reproduces)
5. [Move it into the v3 repository](#5-move-it-into-the-v3-repository)
6. [Branch, judge, and promote inside the repository](#6-branch-judge-and-promote-inside-the-repository)
7. [Export it to your observability stack](#7-export-it-to-your-observability-stack)
8. [Where to go next](#8-where-to-go-next)

If you would rather read working code than prose, these two examples run
offline with no API key at all and cover this walkthrough end to end:

```bash
python examples/v3_repository.py    # sections 5 and 6, end to end
python examples/otel_interop.py     # section 7, both directions
```

## 1. Install

OpenTine supports Python 3.11 through 3.14.

```bash
pip install opentine
```

The core install has no provider SDK in it. Add the one you intend to call:

```bash
pip install "opentine[anthropic]"   # or [openai], [google], [compat], [all]
```

`ollama` needs no extra — it speaks HTTP through the core dependency. Check that
the CLI is on your path and that its signed pricing catalog loaded:

```bash
tine --help
tine pricing check
```

## 2. Your first captured run, with no code

`tine run --model` drives a bundled adapter straight from the command line, so
the first captured run costs one command and no Python file:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
tine run --model anthropic --prompt "Explain what a content-addressed object is"
```

`--model` takes `provider` or `provider:model`. Without a model id the adapter
keeps its own default:

```bash
tine run --model openai:gpt-5.6 --prompt "Explain the current branch" --save first.tine
```

The providers `--model` accepts are `anthropic`, `google`, `ollama`, and
`openai`; the hosted OpenAI-compatible adapters `deepseek`, `glm`, `grok`,
`groq`, `hermes`, `kimi`, `ministral`, `mistral`, `openrouter`, `qwen`,
`together`, and `zai`; and the local OpenAI-compatible runtimes `jan`,
`koboldcpp`, `litellm`, `llama-cpp-python`, `llamacpp`, `lmstudio`, `localai`,
`mlx-lm`, `nvidia-nim`, `sglang`, `tensorrt-llm`, `tgi`, `unsloth`, and `vllm`,
each of which needs no key and points at the localhost URL its server
conventionally listens on. A name outside that set is refused with the full list
rather than guessed at.

Without `--save` the run is written to `.tine_runs/<run-id>.tine` and the id is
printed. `--model` is exclusive with a script argument and with `--harness`:
three run modes competing for one run would silently drop two of them.

**No key handy?** Every later section works on any `.tine` file. Produce one
without a provider by importing a trace you already have — see
[CAPTURE.md](CAPTURE.md) — or by running `python examples/otel_interop.py ./work`,
which writes `./work/imported.tine` for you to substitute for `first.tine` below.

For anything with tools, a budget, or more than one prompt, write the agent in
Python instead:

```python
from opentine import Agent
from opentine.models.anthropic import Anthropic

run = Agent(model=Anthropic("claude-sonnet-5")).run_sync("Explain the current branch")
run.save("first.tine")
```

## 3. Read the run

```bash
tine show first.tine       # the run tree: model steps, tool calls, outcomes
tine cost first.tine       # cost, tokens, and budget state
tine price first.tine      # re-derive the cost now, from what was recorded
tine verify first.tine     # recompute the integrity digest
```

`tine cost` reports the cost recorded at capture; `tine price` recomputes it
post-hoc from the run's `(provider, model, usage)` against the pricing catalog —
`--at YYYY-MM-DD` prices against the catalog effective that day — and writes
nothing. That is how a run imported from somebody else's trace gets a price.

`tine verify` checks the integrity digest only until you ask for more. It fails
closed the moment any of `--key-env`, `--key-file`, `--pubkey`,
`--require-signature`, or `--trust-embedded-key` is present.

Runs are indexed **only while they live in `.tine_runs`** — the directory a
`tine run` without `--save` writes to. For those, four more verbs work:

```bash
tine ls --limit 5
tine tag .tine_runs/<run-id>.tine --add prod
tine search "tag:prod model:gpt"
tine stats --group-by model
```

`tine search` understands `tag:`, `model:`, `status:`, `cost:`, `after:`, and
`before:` predicates plus free text; `cost:` accepts `>`, `>=`, `<`, `<=`, and
`min..max`. `tine ls` exposes the same filters as flags. `tine reindex` rebuilds
`.tine_runs/index.json` if it drifts.

These four read the legacy file index, not a v3 repository — a run you moved
elsewhere with `--save` is still fully usable by every other verb, it is just not
in the index.

Add `--json` to any of these for exactly one JSON object on stdout.

## 4. Fork it, diff it, prove it reproduces

A fork branches from a step and keeps everything before it:

```bash
tine fork first.tine --from-step 1 --save retry.tine
tine diff first.tine retry.tine
tine diff first.tine retry.tine --exit-code   # 0 identical, 1 different
```

`--from-step` accepts a decimal step index, a full step id, or a unique step-id
prefix. Forking never rewrites the source artifact.

Replay re-derives a run. `--mode cache` reuses the recorded steps; `--mode
rerun` re-executes them:

```bash
tine replay first.tine --mode cache --save replayed.tine
tine replay first.tine --verify
```

`--verify` is the proof: it replays into a temporary directory, reads the
artifact back, derives the replay a second time from the source, and compares.
It exits **0** when the run reproduced and **1** on drift. It writes nothing
unless you pass `--save`. `--ignore-cost-drift` lets cost/usage/billing
differences alone still pass; structural drift always fails.

## 5. Move it into the v3 repository

A `.tine` file is one portable artifact. A `.tine/` repository is the object
store: content-addressed `blob`, `event`, `run`, `attestation`, and `annotation`
objects, refs that move under compare-and-swap, reflogs, packs, and indexes.

```bash
mkdir agent-history && cd agent-history
tine init .
tine migrate-v3 ../first.tine --repo . --ref heads/main
tine fsck --repo .
```

`tine migrate-v3` prints the new run oid and an old→new event map. It keeps the
original artifact byte-exact as a legacy blob and records its original
integrity/signature result; a source that fails verification is refused unless
`--allow-unverified` is explicit.

Read what landed:

```bash
tine repo-log heads/main --repo .
tine repo-show heads/main --repo .
tine repo-log heads/main --repo . --json    # event oids, for the next section
```

## 6. Branch, judge, and promote inside the repository

Pick an event oid out of `tine repo-log --json` and branch from it. `--ref` is
required and has no default — the ref you write to is always your decision:

```bash
tine repo-fork heads/main \
    --from-event event:sha256:... \
    --ref experiments/terse \
    --prompt "Answer in one sentence" \
    --repo .
```

Compare the two runs semantically. `tine repo-diff` reports the shared
ancestors, the events only one side has, and which fields changed — it never
line-merges transcripts:

```bash
tine repo-diff heads/main experiments/terse --repo .
tine repo-diff heads/main experiments/terse --repo . --exit-code
```

Attach immutable judgements, then move a release gate:

```bash
tine evaluate experiments/terse --evaluator judge --score quality=0.9 --repo .
tine attest experiments/terse --signer release-manager \
    --claim '{"kind":"approval"}' --repo .
tine promote experiments/terse --name production --repo .
```

`promote` defaults to *expect no existing ref*. Moving a promotion that already
exists requires `--expected-old` naming the value being replaced, and there is
no `--force`:

```bash
tine promote <run-oid> --name production --expected-old <current-oid> --repo .
```

Evaluation and approval attestations are content-addressed, but the `signer`
label is self-asserted unless you attach and independently verify a signature —
the CLI prints `unsigned` rather than implying otherwise.

Search and re-verify at any point:

```bash
tine repo-search "one sentence" --repo .
tine context event:sha256:... --repo .   # only an event's causal ancestors
tine fsck --repo .                       # recompute every id, ref, and link
```

`python examples/v3_repository.py` runs this entire section offline and prints
the output of each verb.

## 7. Export it to your observability stack

`tine export` renders a run as OpenTelemetry GenAI spans — the exact shape
`tine import --format otel-json` reads back, so the two round-trip:

```bash
tine export first.tine                      # OTLP/JSON document on stdout
tine export first.tine --output spans.json
```

Push it to a collector instead of writing a file:

```bash
tine export first.tine --endpoint http://127.0.0.1:4318 --service-name my-agent
tine export first.tine --endpoint https://collector.example/v1/traces
```

`--endpoint` implies `--format otlp`; `--format otlp` on its own falls back to
`$OTEL_EXPORTER_OTLP_ENDPOINT`. `/v1/traces` is appended unless the endpoint
already ends there. The push prints a receipt naming the endpoint, span count,
and HTTP status, and exits non-zero if the collector is unreachable or answers
anything but 2xx.

Because a run carries prompts and completions, a cleartext push is refused
unless the endpoint host is a **literal loopback IP** — `127.0.0.1` or `[::1]`,
not the name `localhost` — or `--allow-insecure` says otherwise.

Going the other way is one command as well:

```bash
tine import spans.json --format otel-json --repo . --ref heads/main
```

[CAPTURE.md](CAPTURE.md) covers every ingestion on-ramp, including the ones that
do not involve OpenTine at runtime at all.

## 8. Where to go next

- [CONCEPTS.md](CONCEPTS.md) — the mental model: events, digests, refs, and what
  verify/fork/diff actually mean.
- [CAPTURE.md](CAPTURE.md) — capture an agent you already have, without
  rewriting it.
- [API.md](API.md) — the public Python surface, one line per name.
- [REPOSITORY.md](REPOSITORY.md) — v3 object semantics, packs, remotes, and MCP.
- [PRICING.md](PRICING.md) — signed catalogs and how a cost is resolved.
- [SECURITY_MODEL.md](SECURITY_MODEL.md) — trust boundaries, redaction, signing.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — the failures newcomers hit first.
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — dev setup and the standing gates.
