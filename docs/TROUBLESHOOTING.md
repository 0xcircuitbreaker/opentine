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

Two cases report `unknown` even though a rate card exists, and both say so in
`billing.warnings` rather than in the status alone:

- `provider did not report usage; cost is unknown` — the call was streamed
  against an adapter that does not request a usage chunk. `Together`, `Mistral`,
  `Ministral`, `Hermes`, and `OpenAICompatible` send nothing by default. Pass
  `include_usage=True` if your endpoint accepts the field.
- `explicit rates were ignored for the different model` — the provider echoed a
  model identifier that resolves to a different rate card than the one
  requested, so an explicit `rates=` override was discarded and the catalog card
  for the reported model was used. The status stays `complete` at list price
  whenever the catalog prices the reported model, and is `unknown` when it does
  not; the override is not reinstated either way.

Both are described in [PRICING.md](PRICING.md).

## `tine fsck` Reports Missing Links

A shallow clone is not the cause. A depth-limited fetch records every cut link in
`.tine/shallow`, and `fsck` treats a recorded boundary ID as present, so a
freshly shallow-cloned repository verifies clean.

Missing-link errors therefore mean an object is absent and not accounted for by
that file: a hand-edited object store, a partially copied `.tine` directory, or a
deleted `.tine/shallow`. Deleting that file does not materialize history — it
converts every boundary into `missing linked object: OID` and takes `fsck` from
clean to failing.

Use `tine fetch REMOTE` to retrieve the objects, without `--depth` for the full
history. `tine fsck --shallow` is unrelated to shallow clones and is not a fix:
it skips link, pack, run-graph, and cycle checking. Do not hand-edit loose
objects or refs.

## An Operation Refuses At The Shallow Fetch Boundary

Readers stop at the boundary the way `git log` does: `log`, `diff`, and
`context_slice` return only what was fetched, and a depth-0 clone returns empty
results rather than failing. Operations that must materialize a whole run refuse
instead:

```
loading run RUN requires EVENT, which is beyond this repository's shallow fetch
boundary; deepen the fetch (fetch/clone with a higher or no --depth) to retrieve it
```

`load_run`, `fork`, `resume`, and recording a new step into a cut run all raise
that error with the operation named. Deepen with `tine fetch REMOTE` without
`--depth`, or clone again without one.

The readers that do not refuse also do not mark what they omitted. `SemanticDiff`
carries no truncation flag, so cost and latency aggregates taken from a shallow
clone silently cover only the events present.

## Remote Ref Update Conflicts

Push uses compare-and-swap. A concurrent writer produces `remote ref changed
concurrently`. Fetch the remote ref, inspect or merge the semantic run choice,
then retry; OpenTine will not overwrite another writer silently.

## The Remote Client Refuses `http://localhost`

`remote requires HTTPS; opt into insecure development explicitly` is raised for
any base URL that is not `https://`, unless the host is a **literal loopback
address**. The check parses the host as an IP address, so `http://127.0.0.1:8787`
and `http://[::1]:8787` are accepted with no opt-in, while
`http://localhost:8787` — the same machine, spelled as a name — is refused. This
is the first thing most developers hit, because `localhost` is the conventional
spelling and `tine serve` listens on `127.0.0.1` by default.

Use the literal address, or pass `--allow-insecure` to `tine fetch`, `tine push`,
and `tine clone`. Bearer credentials are attached to a plaintext loopback client,
so confine both forms to development.

## `tine serve` Exits Before Listening

The server checks its preconditions in this order and exits without starting if
any fails:

- `TINE_REMOTE_TOKEN must contain the development bearer token` — the variable
  named by `--token-env` (default `TINE_REMOTE_TOKEN`) is unset or empty.
- `TINE_REMOTE_TOKEN must contain at least 16 bytes of token material`.
- `TLS --cert and --key are required unless --insecure-dev is explicit` — supply
  a certificate and key, or `--insecure-dev` for plain HTTP.
- `timeout and server limits must be positive` — one of `--timeout`,
  `--request-deadline`, `--max-body-mb`, `--max-upload-mb`, or
  `--max-connections` is below 1.
- `TINE_KMS_KEY is required for encrypted remote storage` — object storage and
  the audit chain are keyed from it. A value that is not base64, or that does not
  decode to 16, 24, or 32 bytes, gives `TINE_KMS_KEY must be a base64 AES key`.
  This precondition is raised from the application factory, so it arrives as a
  `RuntimeError`/`ValueError` traceback rather than a one-line message.

Generate a development key with:

```bash
python3 -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

A successful start prints `OpenTine remote listening on https://127.0.0.1:8787`,
or the `http://` form under `--insecure-dev`. `--host` and `--port` default to
`127.0.0.1` and `8787`.

## Saving Refuses A Step Input Or Run Payload

Both formats enforce at write exactly what the reader enforces, so a run that
saves is a run that loads back. Failing at save leaves the run in memory, where
the value can still be repaired.

- `step and run JSON must be an object to survive a later load; got list` —
  repository blobs are JSON objects. Wrap the value as the message says, in
  `{"value": ...}`.
- `step or run JSON exceeds the structural limit the loader enforces` — the body
  carries more structural tokens (braces, brackets, commas, colons) than the
  budget derived from its own length permits, or nests more than 512 levels deep.
  Summarize or truncate the offending tool result.
- `run nesting or structure exceeds what a .tine artifact can hold` — the same
  rule for the portable artifact.
- `.tine artifact would exceed the size limit every reader enforces
  (268435456 bytes)` — split the run, or save it into a v3 repository.
- `integer exceeds the 4096-digit .tine limit; store it as a string`.

## An Unpaired UTF-16 Surrogate Is Refused

`... holds an unpaired UTF-16 surrogate at PATH` refuses a string that UTF-8
cannot encode. It comes from a truncated `\udXXX` escape — a streamed model or
tool response sliced mid-emoji — or from CESU-8 surrogate bytes emitted by a
non-UTF-8 producer. Neither `.tine` nor the v3 canonical form can represent one,
and readers in other languages disagree about what it means, so the digest would
not be reproducible.

The message names the offending field path. Repair it at the source: OpenTine
will not substitute U+FFFD on your behalf, because doing so would rewrite
recorded model output under a digest that claims fidelity. The writer and the
reader enforce the same rule, so the refusal arrives while the run is still in
memory.

## A CLI Flag Is Refused Instead Of Ignored

Two messages, both exiting 1 before any work is done:

- `FLAG has no effect MODE` — the selected mode never reads that flag.
  `tine run --harness ... --autosave-interval` without `--autosave`,
  `tine fork --prompt` without `--harness`, `tine replay --inspect` with
  `--compare`, `tine migrate --dry-run` with `--save`, `tine sign --overwrite`
  without `--save`, and `tine keygen --force` without `--out` or `--pub` all
  produce it.
- `FLAG_A and FLAG_B cannot be combined: only one takes effect` — two flags
  compete for one slot. `--key-env` with `--key-file`, any two of
  `--key-env`/`--key-file`/`--pubkey`/`--trust-embedded-key` on `tine verify`,
  and `--in-place` with `--save` on `tine migrate`.

These are deliberate. Exiting 0 after silently dropping `--save` writes the
artifact somewhere other than where it was asked to go, and letting precedence
decide between two key flags lets the file being checked pick which key it is
verified against. Drop the flag the mode cannot honour, or switch to the mode
that reads it.

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

`Private/link-local/loopback host denied by policy: HOST` means network policy
blocked a non-global address. Private, loopback, link-local, reserved, and
multicast hosts are all blocked by default to reduce SSRF risk. Use a policy with
`allow_private_hosts=True` only when the workflow intentionally targets a trusted
local service.
