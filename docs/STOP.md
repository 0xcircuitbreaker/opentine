# Fleet-wide fail-closed stop (0.91)

`tine loop stop` (0.58) stops one loop in one repository. A fleet of agents
spread over several repositories needs one stop that reaches every run, and a
way to tell that the runs actually stopped. From 0.91 a repository can be put
under a **stop policy**: every run and loop there must hold a fresh signed
**continue proof** before each step, and halts when it cannot get one.

Without a stop policy nothing changes (D12).

## The pieces

| Piece | What it is | Where |
| --- | --- | --- |
| Stop channel | A signed append-only transparency log (tiled Merkle tree, signed-note checkpoint) of stop and continue proofs | a directory shared by the fleet, `origin = opentine-stop/<fleet>` |
| Stop policy | The fleet id, the channel path, the channel's verifier key, the freshness window `window_s` (default 300), the allowed clock skew `skew_s` (30) and the watchdog interval `watchdog_s` (10) | `.tine/stop-policy.json` (`opentine.stop-policy/1`), held as `stop-policy:<fleet>` |
| Fleet stop | An attestation, claim `opentine.fleet-stop/1` | the issuer's repository (held as `fleet-stop:<fleet>`) and the channel |
| Continue proof | An attestation, claim `opentine.stop-continue/1`, for one run | the issuer's repository and the channel |
| Compliance record | An attestation, claim `opentine.stop-compliance/1`, signed by the runner | the runner's repository (held as `stop-compliance:<run>`) |

None of these is a new object kind, and `tine verify` gains no new codes. The
claim shapes are published as `opentine-fleet-stop-1`,
`opentine-stop-continue-1`, `opentine-stop-compliance-1` and
`opentine-stop-policy-1`.

## Who may sign

Stops and continue proofs count only when Ed25519-signed, when `signer` names
the key that signed, and when that key is a pinned `stopper` or `policy` key of
the owner-signed trust bundle. A key the bundle also names as `optimizer` is
never one. `tine stop issue` and `tine stop continue` refuse any other key
before writing anything. Compliance records are signed by the runner key and
count as verified only for a pinned `runner` key.

## What a runner checks, before each step

`tine record` checks before forwarding each model call; the agent loop behind
`tine run --model` checks before each model call and each tool call; the
reference loop checks before each iteration (`tine stop status --run`). A
watchdog repeats the check every `watchdog_s` seconds while a long step runs.

The runner reads the channel and verifies every entry against the checkpoint
and the pinned verifier key. It halts (fail closed) with:

| Code | When |
| --- | --- |
| `stop.channel-unreachable` | the channel cannot be read or does not verify |
| `stop.channel-rollback` | the log is shorter than, or does not extend, what this runner read before |
| `stop.stopped` | the log holds a stop entry (verified or not: a stop is fail safe) |
| `stop.no-continue` | no valid continue proof names this fleet and run |
| `stop.continue-rollback` | the newest proof's `seq` is lower than one accepted before |
| `stop.continue-unbound` | the proof is bound to another channel key, or to a checkpoint this log does not extend |
| `stop.continue-future` | the proof is dated later than now plus `skew_s` |
| `stop.continue-stale` | the proof is older than the window (the smaller of the policy's and the proof's) |

A continue proof is bound to the fleet, the run id, a per-run sequence number
and a checkpoint of the channel the signer saw, so it cannot be replayed for
another run or fleet, copied into another channel, or rolled back. Once a
runner halts it stays halted; a stopped fleet is never un-stopped (restart under
a new fleet id). These codes are command-level codes, not `tine verify` codes.

## Children inherit the stop

`tine record` starts its command as one killable tree: its own process group
and, on Linux, the subreaper supervisor that also catches descendants that
leave the group (`setsid`); on Windows a kill-on-close job object. A halt kills
the whole tree, so sub-agents and their children stop with it.

## Stop compliance

After a halt the runner signs a compliance record: the halt code, the stop
entry, when the halt was decided and when the tree was gone
(`time_to_halt_ms`), the time since the stop's own `stopped_at`
(`since_stop_ms`), the processes of the tree still alive
(`residual_processes`, with how they were counted), and the actions forwarded
or refused after the halt. It is `compliant` when the tree was gone within one
watchdog interval, nothing was left, nothing was forwarded after the halt and,
for a fleet stop, the halt came within one watchdog interval plus `skew_s` of
the stop's `stopped_at` (a runner that only halts once its proof goes stale is
late). The residue is counted before any second kill, so a process that
survived the first one is reported, then killed. Whoever reads the record
recomputes `compliant` from its signed numbers; the claimed flag alone counts
for nothing. A record that
is not compliant, does not verify, or is not by a pinned runner key opens a
`stop:<record>` item in the oversight queue (`tine oversight queue`).
`tine stop compliance` lists the records; a non-compliant one is advisory
unless `--strict`.

## Setting it up

```console
# once, by whoever runs oversight: create the channel (its log key stays here)
tine stop init --channel /shared/stop --fleet fleet-a --repo ./repo-a
# in every other repository of the fleet: pin the same channel
tine stop init --channel /shared/stop --fleet fleet-a --vkey "$VKEY" --repo ./repo-b
# the oversight side keeps runs alive with fresh proofs ...
tine stop continue --channel /shared/stop --fleet fleet-a --run job-1 --key policy.key
# ... and a run under the policy names its run id and runner key
tine record --repo ./repo-b --stop-run job-1 --stop-key runner.key -- ./agent
# stop every run of the fleet
tine stop issue --channel /shared/stop --fleet fleet-a --key stopper.key --reason "halt"
```

## Tamper resistance

* Deleting the policy file does not lift the requirement: the policy is held,
  and a held policy whose file is missing, or differs from every installed
  version, fails closed. Rewriting it can only make runs halt: proofs are bound
  to the channel key and fleet, and the smaller window wins. The file is also
  on the `policy-files` integrity surface.
* Deleting or rewriting the channel makes it unreachable or rolled back: runs
  halt.
* The channel's log key signs checkpoints; runners need only its verifier key.
  Keep the log key with the oversight side.

## Limits

* Fail closed makes the channel a single point of failure for the fleet's
  availability: an unreachable channel halts every run. That is the intent of
  a stop policy; repositories without one are unaffected.
* Freshness rests on the signer's and the runner's clocks; `skew_s` bounds how
  far they may disagree.
  A runner reads the wall clock once and then advances it only by the
  monotonic clock, so setting the system clock back mid-run keeps no proof fresh.
* A runner remembers what it has read only while it runs: a new runner cannot
  tell that a whole channel was replaced by an older copy of itself (it still
  needs a fresh proof within the window, so the replay is bounded by `window_s`).
* `tine run --harness` and script mode check once before they start; only
  `tine record` and `tine run --model` check before every call. An in-process
  tool call that does not return cannot be killed; the watchdog marks the run
  halted and the next check stops it.
* A runner checks the whole log on each step, so cost grows with the log.
* Residual processes are counted from `/proc` on Linux, by probing the process
  group elsewhere on POSIX, and are taken as zero after closing the job object
  on Windows.
