# Tripwires (0.91)

A tripwire is a rule over a signal the repository already records: when the
signal crosses a threshold, the trip is signed, held and sent for review, and a
`stop` tripwire also stops the loop. Tripwires are kept in a signed registry
that only a pinned `policy` key can change.

## The registry

```
tine tripwire add ID --metric M --threshold 1 --key KEY [--op >=|>|<=|<] [--scope S]
                  [--action flag|stop] [--decoy sha256:HEX]... [--replace]
tine tripwire remove ID --key KEY
tine tripwire list
```

Each change signs a new registry version: an attestation (an existing object
kind) under the claim convention `opentine.tripwire-registry/1`:

```json
{"convention": "opentine.tripwire-registry/1", "serial": 2,
 "previous": "attestation:sha256:...",
 "tripwires": [{"id": "decoy", "metric": "decoy.touches", "op": ">=", "threshold": 1.0,
                "scope": "stream:rl", "action": "stop", "decoys": ["sha256:..."]}],
 "at": "2027-01-15T08:00:00Z"}
```

Every version lists the whole registry, and `previous` names the version
before it, so the versions form a chain. A version is held under
`tripwire:registry:SERIAL`, which `tine hold release` refuses.

A version counts only when its Ed25519 signer is the key that signed it and
that key is a `policy` key of the owner-pinned trust bundle that is not also an
`optimizer` key. `add` and `remove` refuse any other key
(`tripwire.registry-signer`, exit 1). The registry is read from every
attestation in the object store, held or not, so:

| Finding (`fail:`) | Cause | Effect |
| --- | --- | --- |
| `tripwire.registry-signer` | A version signed by another key, or not signed by its key | Ignored; reported |
| `tripwire.registry-invalid` | A malformed version by a policy key | Ignored; reported |
| `tripwire.registry-unheld` | A counted version whose hold row was dropped | Reported |
| `tripwire.registry-fork` | Two versions with the same serial | Registry `broken` |
| `tripwire.registry-chain` | A version that does not continue the chain | Registry `broken` |
| `tripwire.registry-rollback` | The head is below the pinned `min_serial` | Registry `broken` |
| `tripwire.registry-missing-version` | A held version whose object is gone from the store | Registry `broken` |
| `tripwire.registry-missing` | The registry is `broken` (under any rule), or the pinned rule requires one that is `absent` or `unpinned` | Fails closed (below) |

These are command-level codes, not `tine verify` codes.
A held version that does not count stays a finding, so `tine tripwire list`
and `check` keep exiting 1 after an attempt to edit the registry around the
command: the attempt is evidence, and it is reviewed rather than cleared.

### The pinned rule

The owner-signed trust bundle may carry a `tripwires` section
(`tine trust bundle create --tripwires FILE`):

```json
{"version": 1, "required": true, "min_serial": 3}
```

With `required`, a registry that is absent, unpinned or broken **fails closed**:
`tine tripwire check --key` signs a trip with `tripwire` null and writes a `*`
stop token. `min_serial` refuses a rollback to an older version. Under a
pinned owner, a bundle that is missing or does not verify also requires a
registry. Without the section, a repository with no tripwires behaves as
before (owner decision D12).

## Signals

| Metric | Scope | Value |
| --- | --- | --- |
| `suspicion.flags` | `*`, `stream:S`, `agent:ID`, `session:ID` | Cumulative-suspicion and doom-loop flags (docs/MONITORS.md) |
| `suspicion.score` | same | The highest summed score of a matching subject |
| `monitor.non-allow` | same | Monitor outcomes other than `allow` in the verified coverage ledgers |
| `monitor.events` | same | Events the monitors evaluated |
| `ingest.events` | same | Captured events of the signed ingest batches (docs/INGEST.md) |
| `decoy.touches` | same | Captured events that contain a registered decoy |
| `budget.LIMIT` | `budget:loop:NAME`, `budget:agent:NAME`, `agent:NAME` | The spend total of a budget subject (docs/BUDGETS.md) |

Every value is recomputed from held, signed records at the evaluation time
(`--now-ms`, default now). A signal that cannot be read trips (fail closed),
with the error in the result.

### Decoys

`decoy.touches` takes the `sha256:` digests of decoy credentials, file paths
or endpoints; the registry never holds the decoys themselves. Every string in
a captured event is compared by digest whole, split at whitespace, quotes,
`=`, `,`, `;`, `|` and brackets, and each such token split again at `/`, `?`,
`#` and `&`. So a decoy path `/home/agent/.aws/credentials-backup` matches
`cat /home/agent/.aws/credentials-backup | base64`.

## Checking

```
tine tripwire check [--key KEY] [--now-ms MS]
tine tripwire trips
```

`check` evaluates every tripwire and exits 1 when one trips or the registry
has a finding. With `--key` it records one trip per tripwire and registry
version: an attestation under `opentine.tripwire-trip/1`

```json
{"convention": "opentine.tripwire-trip/1", "tripwire": {...}, "registry": "attestation:...",
 "serial": 2, "value": 1.0, "evidence": ["annotation:sha256:..."], "action": "stop",
 "stop": "attestation:sha256:...", "reason": "tripwire decoy: ...", "at": "..."}
```

held under `tripwire:trip:ID` (never released). The signer must be a pinned
`monitor`, `runner` or `policy` key that is not an `optimizer` key
(`tripwire.trip-signer`). A trip already recorded for the same tripwire and
registry version is not written again; a trip by another key counts for
nothing and does not suppress a real one.

A `stop` action first writes an `opentine.monitor-stop/1` stop token
(docs/MONITORS.md) and names it in the trip's `stop` field. The token's scope
is the tripwire's `agent:` or `session:` scope, `agent:ID` for a
`budget:agent:ID` scope, and `*` otherwise. Every gate that honours a stop
token (hooks, the MCP proxy) then blocks; there is no un-stop. A stop service
that propagates stops to other repositories can treat a trip with a `stop`
field the same way it treats a stop token.

Each held trip is a `tripwire:ATTESTATION` item in the oversight queue (route
`source = "tripwire"`, docs/OVERSIGHT.md), including trips that do not count,
so they are reviewed rather than hidden.

## Limits

- Signals are only as complete as what is captured: an action that never
  reaches an ingest stream or a monitor ledger is invisible to a tripwire.
- Captured events are redacted before they are stored (docs/INGEST.md). A
  decoy that looks like a credential may be redacted before it is compared;
  register decoys the redaction leaves alone, or capture the stream with
  `"redact": false`.
- `check` runs when it is called. Run it on a schedule, or after each ingest
  batch, for the stop to follow the trip promptly.
- A writer that can delete objects from the store (not only hold rows) can
  remove registry versions; `min_serial` in the pinned rule bounds how far
  back that can go.

## JSON

`--json` prints `tine-cli-tripwire/1`
(`docs/schemas/tine-cli-tripwire-1.schema.json`). The claims are published as
`opentine-tripwire-registry-1` and `opentine-tripwire-trip-1`: claim
conventions, not object kinds.
