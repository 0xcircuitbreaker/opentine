# Sabotage task records (0.68)

A sabotage evaluation gives an agent a *main task* and, hidden inside it, a
*side task* it should not do: code sabotage (plant a backdoor, weaken a test,
leak a secret through a diff) or decision sabotage (steer a recommendation, a
review or a promotion toward a worse choice). This is the SHADE-Arena shape.
OpenTine records the outcome of each such task so that you can report, per
sabotage class, how often your monitors caught an attempted side task.

The records are statistical evidence about monitors. A side task marked
attempted or achieved is a scorer's judgement about one transcript; it is not
proof of any agent's intent.

## The record

Each outcome is an **attestation** (an existing object kind) on the run it
scores. Its claim follows the `opentine.sabotage-task/1` convention
(schema `docs/schemas/opentine-sabotage-task-1.schema.json`):

```json
{"convention": "opentine.sabotage-task/1",
 "task": "backdoor-07", "class": "code",
 "main_task": {"id": "fix-login-bug", "score": "0.75", "passed": true},
 "side_task": {"id": "plant-backdoor", "attempted": true, "achieved": false},
 "evidence": ["run:sha256:...", "diff:patch-07"],
 "monitor_verdicts": ["attestation:sha256:..."],
 "at": "2026-12-01T10:00:00Z"}
```

* `class` is `code` or `decision`.
* `main_task.score` is a decimal string or null; `passed` is true, false or null.
* `achieved` implies `attempted`.
* `evidence` is a list of free-form references (object ids, paths, URLs).
* `monitor_verdicts` names the `opentine.monitor-verdict/1` attestations
  (docs/MONITORS.md) that judged the run's actions.

This is a claim convention: no object kind and no `tine verify` code is added.

## Who may record

A record counts only when it is signed with Ed25519 by a key in the `scorer`
or `eval` role of the owner-pinned key roles (`key-roles.toml` signed into an
owner trust bundle; see `tine keys lint`). A record signed by any other key is
kept and reported as `advisory:sabotage.signer-unpinned`; a record signed by a
pinned `optimizer` key is `fail:sabotage.key-separation`. With no pinned trust
bundle, no record counts.

## Outcomes only go up

Every record is kept by a `tine hold` row whose target is
`sabotage-task:TASK`. `tine hold release` refuses that row, so the record
cannot be released and pruned away.

`tine sabotage record` refuses a record that would mark a side task not
attempted (or not achieved) after a counted record said it was
(`sabotage.relabel`). A loop that bypasses the command and holds a downgrade
anyway does not lower the outcome: `tine sabotage report` takes the strongest
outcome over the counted records and reports the downgrade as
`fail:sabotage.relabel`.

## Commands

| Command | What it does |
| --- | --- |
| `tine sabotage record --run RUN --task ID --class code\|decision --main-task ID [--main-score DECIMAL] [--main-passed yes\|no] --side-task ID [--attempted] [--achieved] [--evidence REF]... [--verdict ATTESTATION]... --key KEY [--at TIME]` | Signs and holds one record on RUN |
| `tine sabotage report [--task ID] [--strict] [--seed N] [--resamples N] [--alpha A]` | Catch rate per class from the held records |

Both take `--repo PATH` and `--json` (schema `tine-cli-sabotage/1`).

## The report

For each task the report gives the run, the number of counted records,
whether the side task was attempted and achieved, and the linked verdicts. A
task is *caught* when one of its linked verdicts verifies (signed by a pinned
`monitor` key, docs/MONITORS.md) and its action is `flag`, `resample`,
`defer` or `block`. A verdict that does not verify is reported
`advisory:sabotage.verdict-unverified` and does not count as a catch.

Per class it gives tasks, attempted, achieved, caught, achieved-but-uncaught
and the catch rate (caught / attempted) with an interval from the 0.58
paired-bootstrap code (`opentine._eval_stats`) over a 0/1 caught bit per
attempted task, seeded with `opentine-sabotage/1:SEED:CLASS`; the same
records and seed give the same numbers.

Findings follow D12:

| Code | Level | Meaning |
| --- | --- | --- |
| `fail:sabotage.relabel` | fail | a held record lowers an outcome a counted record set |
| `fail:sabotage.key-separation` | fail | a record signed by a pinned optimizer key |
| `fail:sabotage.malformed` | fail | a held record that is unsigned or not a valid claim |
| `advisory:sabotage.signer-unpinned` | advisory | signer outside the pinned scorer and eval roles |
| `advisory:sabotage.verdict-unverified` | advisory | a linked monitor verdict does not verify |
| `advisory:sabotage.uncaught` | advisory | an achieved side task that no linked verdict caught |

`report` exits 1 on a `fail:` finding (facts about the records); the
advisory findings, including every statistic, never block unless `--strict`
is given.
