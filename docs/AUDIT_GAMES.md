# Auditor runs, blind audit games and judge provenance

This page covers three related records added in 0.65:

- **judge provenance**: what an LLM judge was (model, prompt, rubric,
  sampling), pinned inside every signed eval verdict it produced;
- **auditor runs**: Petri and Bloom transcripts recorded as ordinary runs
  tagged `role=auditor`;
- **blind audit games**: the auditor works without knowing which target it
  is auditing, and the order of findings and reveal is checkable offline.

None of them adds an object kind or a `tine verify` code. Each is a claim
convention on objects that already exist.

## Judge provenance

An `llm-judge:PROVIDER[:MODEL]` scorer describes itself as an
`opentine.judge-provenance/1` document:

```json
{"convention": "opentine.judge-provenance/1",
 "model": "ollama:tiny",
 "prompt_digest": "sha256:<hex of the prompt template, UTF-8>",
 "rubric_digest": "sha256:<hex of the rubric text>",
 "sampling": {"temperature": "0"}}
```

`rubric_digest` is `null` when no rubric was given. Sampling values are
decimal strings.

The scorer's `scorer_version` is `jp1+sha256:` followed by the SHA-256 of the
document's canonical JSON. `scorer_version` is a field of the signed body of
every `tine-eval-verdict/1`, so the provenance is covered by each verdict's
signature. `tine eval run` writes the document next to the verdicts as
`judge.json`, and each judge run's metadata carries it too.

```sh
tine eval run data.jsonl --scorer llm-judge:ollama:tiny --judge-rubric rubric.md \
    --key scorer.key --out evals/judged
tine eval verify evals/judged
```

`tine eval verify` recomputes the pin from `judge.json`:

- If `judge.json` is edited, for example to a different rubric digest, the pin
  no longer matches the signed `scorer_version`. The eval fails with
  `eval.summary-mismatch`, the same check that catches an edited `eval.json`.
- If the verdicts are also edited so `scorer_version` matches, their
  signatures no longer verify: `eval-verdict.bad-signature`.

The verdict format and its three verifiers (Python, the `.pyz` and
TypeScript) are unchanged. The only change is the value an `llm-judge` scorer
writes in a field those verifiers already check. Before 0.65 that value was
`1+sha256:<16 hex>`, so old evals still verify; they just carry no provenance
document.

`--judge-rubric FILE` appends the rubric to the judge prompt under a
`Rubric:` heading.

## Auditor runs

```sh
tine auditor import-petri transcript.json --repo .
```

This reads a Petri transcript (`metadata` plus `events`, each with a `view`
and an `edit.message`) or a Bloom transcript (`evaluator_model` and a
top-level `messages` list). It records one ordinary run:

| Field | Value |
| --- | --- |
| tags | `role=auditor`, `petri` |
| `metadata.audit` | `role`, `source`, `transcript`, `auditor_model`, `target_model`, `judge_model`, `scores` |
| steps | one `model` step per message; `inputs.speaker` is `auditor` or `target`, `model_info` is the model that spoke |
| last step | the judge's scores and summary (`speaker: judge`) |

In the target's view, the auditor writes the system, user and tool turns, so
those are recorded as auditor steps. Only assistant turns in the target's
view are target steps.

The reader parses the JSON log format directly and does not need
`inspect_ai`. It is bounded: at most 16 MiB of input, the import guard's
nesting and token budget, 10 000 messages and 1 MiB of text per message.
Malformed input is refused with an error rather than a traceback.

## Blind audit games

A game has three records. Each is an Ed25519-signed **attestation** on the
auditor run, with claim convention `opentine.audit-game/1`, and each is held
under `audit-game:GAME`. `tine hold release` refuses these holds, so a loop
cannot delete the record of a reveal.

```sh
# 1. Import blind: the target becomes a commitment; the secret stays with the owner.
tine auditor import-petri transcript.json --blind secret.json --objective "..." --repo .
# 2. The game owner seals.
tine auditor seal RUN --game g1 --secret secret.json --key owner.key --repo .
# 3. The auditor submits findings.
tine auditor findings RUN --game g1 --findings findings.md --verdict concern \
    --key auditor.key --repo .
# 4. The owner reveals.
tine auditor reveal RUN --game g1 --secret secret.json --key owner.key --repo .
# 5. Anyone checks, offline.
tine auditor check --repo .
```

| Step | Claim fields |
| --- | --- |
| seal | `commitment`: `sha256:` of the canonical JSON of `{target, objective, nonce}` |
| findings | `seal` (the seal's id), `findings_digest`, `verdict` (`concern` or `no-concern`) |
| reveal | `seal`, `findings` (the findings' id, or null), `target`, `objective`, `nonce` |

Every claim also has `convention`, `game`, `step` and `at`. The schema is
`opentine-audit-game-1`.

With `--blind`, the stored run names the target only as
`sealed:sha256:...`. Message text is imported as written, so a transcript in
which the target states its own name still shows that name.

### What `tine auditor check` reports

These follow D12. A `fail:` finding is a fact about the records and exits 1.
An `advisory:` finding is reported and blocks only with `--strict`.

| Code | Meaning |
| --- | --- |
| `fail:audit-game.reveal-before-verdict` | the reveal names no findings, names findings other than the latest, or the findings were signed after it |
| `fail:audit-game.commitment-mismatch` | the reveal does not open the seal, or the findings name another seal |
| `fail:audit-game.unsealed` | the game has records but no signed seal |
| `fail:audit-game.unsigned` | a held record is not a signed `opentine.audit-game/1` claim |
| `advisory:audit-game.auditor-unpinned` | the findings' key is not in the pinned `auditor` role |
| `advisory:audit-game.unrevealed` | the target is still sealed |

A reveal names its findings by content-addressed id, so it cannot have been
written before those findings existed. If findings are submitted after a
reveal, they are the latest findings, and the reveal does not name them.

## The `auditor` key role

`.tine/key-roles.toml` takes an `auditor` role. Like every power-granting
role, it counts only when it comes from the owner-signed trust bundle
(docs/LINEAGE.md, docs/INTEGRITY.md). It is guarded: `tine keys lint` reports
`fail:key-separation.shared` when an optimizer key also holds an auditor key.

## Inspect logs

Plan item 0.65 also lists an Inspect `.eval` log importer and exporter, an
Inspect hook and a METR task-standard importer. They are not in this release.
