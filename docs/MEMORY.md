# Memory provenance and quarantine

Team memory (docs/PROMPTS_AND_MEMORY.md) puts signed notes into an agent's
context. From 0.61 a repository can also answer the reverse question: which
runs, and which self-modification variants, were served a given note. When a
note turns out to be wrong or planted, `tine memory quarantine` stops it being
served and lists everything it reached.

## What a run records

When a note is served while a run is being captured, the served note digests
(the blob oids of the signed notes) are recorded in that run's own step
evidence: one `tool` step whose attributes hold

```json
{"opentine.memory.served": ["blob:sha256:...", "..."]}
```

and whose inputs hold the recall query. The step is an ordinary event of the
run, content addressed with the rest of it.

```text
tine memory recall 'deploy' --record-to heads/agent    # the run still capturing
```

In-process capture uses `opentine._memory_served.record_with(recorder, rows,
query)`. Recording is refused for a run that is finished (`completed`,
`failed`) or already attested: a signed run is never amended, so a run cannot
be said afterwards to have seen a note it did not see, or the reverse.

## Provenance is a claim convention, not a new object

Memory provenance adds no object kind and no `tine verify` codes (FREEZE.md:
the `memory-provenance` predicate, E3, was not granted). It is the frozen-safe
form:

- the note is signed (`opentine.memory`, SPEC 4.22) by a key on the team file;
- the served step is part of the consuming run, so any attestation over that
  run, and its transparency-log entry, covers which notes the run was served;
- an attestation may name the convention in its claim
  (`"convention": "opentine.memory.served"`); verifiers give such a claim no
  verdict, as for every claim without a granted checker.

## Assurance

`tine memory recall QUERY --min-assurance TIER` keeps only notes whose
`subject` run reaches the tier (docs/SECURITY_MODEL.md). A note's tier is the
tier its subject run's capture claims, capped at `T1`, because a stored run
carries no proxy witness that can be checked here; a note with no subject run,
or whose subject run is not stored, is `T0`. Each row then carries
`assurance`.

## Quarantine

```text
tine memory quarantine blob:sha256:... --key me.key --why 'planted instruction'
tine memory served blob:sha256:...       # the same listing, without quarantining
```

A quarantine is an ordinary memory note that `supersedes` the quarantined note,
carries the tag `quarantine` and says why. It is signed, stored under
`memory/`, and also kept as a held blob (`tine hold` target
`memory-quarantine:NOTE:RECORD`), which `tine hold release` refuses. Readers
take the union of the refs and the held copies, so deleting the quarantine's
ref serves nothing again; an unreadable holds file serves no notes at all.

A quarantine counts when it verifies under `.tine/memory-team.json`; with no
team file, any record whose own signature verifies counts, because counting
one too many only refuses more. Recall (the CLI and MCP `recall`) never
serves a quarantined note or a quarantine record.

A quarantine also covers copies: a note with the same scope, topic and text
(case and whitespace folded) under a different oid is treated as quarantined
by recall, `promote` and `lineage`, so re-adding the note with a new
`created_at` or author does not launder it. A paraphrase is a different note
and needs its own quarantine.

The command lists:

- `runs`: every stored run that lists a step serving the note (each step of a
  capture advances the run object, so every version of a run after the serving
  step is listed);
- `variants`: every lineage variant (docs/LINEAGE.md) whose mutation run, or a
  run its eval verdicts scored, is one of those runs.

## Promotion and lineage

- `tine promote` refuses a candidate run that was served a quarantined note:
  `promote.memory-quarantined`.
- `tine lineage check` and `why` report `lineage.memory-quarantined` for each
  variant on the walked ancestry whose mutation or eval runs consumed a
  quarantined note, and exit 1.

These are command outputs only, like `lineage.score-tainted`; the shared
lineage fixture and the TS port are unchanged.

## The derived index

`.tine/index/memory-served.sqlite` holds one row per (note, run, serving step).
It is derived and rebuildable: deleting it loses nothing. Its `meta.source` is
a digest of every stored run and event id, so a new run or event makes it
stale and the next query rebuilds it (staged, then moved into place). A query
against a fresh index reads no objects, so tracing a note to its consumers
costs one indexed lookup however many runs the repository holds.

Anyone with write access can also write the index, including a `meta.source`
that matches, so the index is never trusted for a decision: `promote` and
`lineage` read served steps from the runs themselves, and `tine memory
quarantine` rebuilds the index before it lists consumers. `tine memory served`
uses the cached index and is a convenience only.
