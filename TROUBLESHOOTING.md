# Troubleshooting

## `tine verify` Fails

- `missing integrity digest`: the file was created before integrity metadata was added or was hand-edited without metadata.
- `malformed digest`: `metadata.integrity.digest` is not a 64-character SHA-256 hex digest.
- `digest mismatch`: the covered artifact body changed after the digest was written.
- `unsupported .tine format_version`: the portable artifact is not readable v1/v2.

`Run.load()` does not automatically reject checksum failures. Use `tine verify` as an explicit trust check before consuming artifacts from outside your workspace.

## Pricing Is `unknown` or `partial`

Run `tine pricing show PROVIDER MODEL` to check for an exact effective card and
`tine pricing check` to verify the bundled signature. OpenTine never substitutes
another provider's rate. Add a hashed workspace/user overlay for new models,
enterprise discounts, direct Hermes pricing, or local infrastructure cost.
`partial` means the known subtotal is still available but at least one observed
dimension has no rate.

## `tine fsck` Reports Missing Links

Use `tine fetch` to retrieve the missing objects. A deliberately shallow fetch
records omitted boundary IDs in `.tine/shallow`; deleting that file does not
materialize history and will make deep verification fail. Do not hand-edit
loose objects or refs.

## Remote Ref Update Conflicts

Push uses compare-and-swap. Fetch the remote ref, inspect or merge the semantic
run choice, then retry; OpenTine will not overwrite another writer silently.
Non-loopback clients require HTTPS, and the reference server requires
`TINE_KMS_KEY` plus `TINE_REMOTE_TOKEN`.

## Live Ollama Tests Skip

Confirm Ollama is reachable and the validation models are installed:

```bash
ollama list
ollama pull llama3.1
ollama pull qwen3
pytest tests/test_live.py --provider ollama -q -rs
```

Set `OLLAMA_HOST` if the daemon is not at `http://localhost:11434`.

## Live Harness Tests Skip

Harness tests skip when the requested CLI is not installed or not authenticated. Install and authenticate the CLI first, then rerun the specific gate:

```bash
pytest tests/test_live_harness.py -m live_harness --agent-harness codex -q
pytest tests/test_live_harness.py -m live_harness --agent-harness kimi-code -q
```

For custom CLIs, use:

```bash
pytest tests/test_live_harness.py -m live_harness --agent-harness generic --harness-command "your-agent run"
```

## Shell Or Python Tools Return Disabled

This is the default. Pass an explicit `ShellPolicy(enabled=True, ...)` or `PythonPolicy(enabled=True, ...)` only for trusted workflows.

## Network Fetch Blocks Local Hosts

Network policy blocks private, loopback, link-local, reserved, and multicast hosts by default to reduce SSRF risk. Use a policy with `allow_private_hosts=True` only when the workflow intentionally targets a trusted local service.
