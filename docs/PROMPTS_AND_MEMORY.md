# Prompts, team memory and push-triggered evals (0.47)

Three pieces that make an eval comparison reproducible and keep what a team
learned next to its runs.

## The prompt registry

`tine prompt push NAME --template TEXT --key KEY` signs version 1 of a prompt;
each later push signs the next version, chained to the previous one by its
digest and signed by the same key (`opentine.prompt`, SPEC 4.21). Labels such
as `production` or `staging` point at a version and move; versions never
change.

```text
tine prompt push review --template 'Review {{diff}} against {{policy}}' --key me.key --label staging
tine prompt label review production           # production -> the newest version
tine prompt get review@production --var diff=@- --var policy=strict
tine prompt link review@production run:sha256:...
tine prompt verify review --pubkey me.pub
```

`prompt link` records the version's name, number and digest in the run's
annotation, so a run says which prompt bytes produced it. An eval whose judge
uses a registered prompt (`judge_prompt` in `.tine/evals.toml`) pins that
prompt's bytes in every signed verdict.

## Team memory

A memory note (`opentine.memory`, SPEC 4.22) is a signed piece of team
knowledge: a scope, a topic, at most 8 KiB of text, tags, and optionally the
run it is about or the note it replaces.

```text
tine memory trust alice.pub                  # who the team trusts
tine memory add testing 'Run the suite with the venv python' --key me.key --tag ci
tine memory recall 'venv tests'
tine memory sync --remote origin
```

Only notes signed by a key in `.tine/memory-team.json` are listed, recalled or
accepted by `sync`; a note that another trusted note supersedes is hidden.
`tine mcp`'s `recall` tool returns the same notes beside the runs it finds, so
an agent sees them; they are text to weigh, not instructions.

## Push-triggered evals

```toml
# .tine/evals.toml
[defaults]
min_pass_rate = 0.9

[[eval]]
name = "smoke"
dataset = "evals/smoke.jsonl"
scorer = "exact"

[[eval]]
name = "judged"
dataset = "evals/judged.jsonl"
scorer = "llm-judge:ollama:llama3"
judge_prompt = "judge@production"
```

`tine eval ci --key KEY` runs each eval, signs its verdicts into
`.tine/evals/NAME/`, and exits 1 when any eval misses its `min_pass_rate`. In
GitHub Actions, the gate action's `evals-config` input runs it on every push
(with the signing key from a secret) and verifies the folders it wrote; on a
self-hosted runner or a laptop it is the same command.

## MCP tasks

`tine mcp` supports MCP 2025-11-25 tasks: a `tools/call` with `task` returns a
task id at once and runs the tool in the background; `tasks/get`,
`tasks/result`, `tasks/list` and `tasks/cancel` follow it (SPEC 8.20).
