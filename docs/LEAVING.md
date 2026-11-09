# Leaving the hosted service

Everything you keep on a `tine serve` remote, the hosted service included, can
leave it in formats you can read without that server. You can take it to
another `tine serve` you run yourself, or to a plain local repository, and
`tine verify --offline` gives the same report there. This is a 1.0 promise
(ROADMAP 0.50, "leave the hosted service"). CI tests it on every push to
`main` (the `leave-service` job in `.github/workflows/ci.yml`, running
`tests/test_050_leave_service.py`), so every release from 0.50 on has passed it.

## In three commands

```sh
# 1. Export: needs a token that may read the tenant (and list its share links).
tine tenant export --remote https://tine.example/v1/tenants/acme \
    --token-file ~/.config/opentine/acme.token --out acme-export

# 2a. Import into a fresh tine serve (a writer token, the same tenant name) ...
tine tenant import acme-export --remote https://new.example/v1/tenants/acme \
    --token-file new.token

# 2b. ... or into a local repository, under the same ref names.
tine init mine && tine tenant import acme-export --repo mine

# 3. Verify offline, in each place you imported to.
cd mine && tine verify . --offline --json > verify.json
```

`--remote` also takes a remote name from `tine remote add`. Add `--json` to
either `tenant` command for a `tine-cli-tenant-1` document.

## What the export folder holds

Every file uses a format that was frozen at 0.48. The export adds no new
format.

| File | Format | Holds |
| --- | --- | --- |
| `tenant.tbundle` | `opentine-bundle/1` ([REPOSITORY.md](REPOSITORY.md), bundles) | every ref of the tenant (`heads/*`, `tags/*`, `annotations/*`, ...) and every object they reach: runs, events, blobs, attestations, annotations. Its `tombstones` key carries the signed tombstone of each purged blob, and its `signatures` key carries any `tine-sig/3` sidecar blocks. |
| `reviews/ID.json` | `opentine-review-bundle-1` (SPEC 4.20) | each Review with every version and gate decision, as their reviewers signed them |
| `project/NNNNNN.json` | `opentine-project-1` (SPEC 4.16) | every project manifest version, oldest first, as its owner signed it |
| `log/checkpoint.json`, `log/entries.json` | the `transparency/checkpoint` and `log/entries` API responses | the server's signed log checkpoint and this tenant's log entries |
| `shares.json` | the `GET shares` API response | share-link ids, runs, states and expiry (never a token) |

`tine bundle verify acme-export/tenant.tbundle` checks the bundle without
importing anything. `tine-verify.pyz` checks each `reviews/ID.json` with no
opentine installed.

## What moves, and what does not

- **Runs, refs, attestations and annotations** move unchanged. Their oids are
  content hashes, so the bundle a fresh server exports again is byte-identical
  to the first one. The test checks this.
- **Signatures** live inside the objects they sign, or in `tine-sig/3`
  sidecars that the bundle carries, so they move unchanged. The server never
  signed any of them.
- **Tombstones** move with the bundle. A purged blob stays purged on the new
  side, and `fsck` still reports its content as unavailable. A run whose blob
  was purged fails `verify` in the same way in every copy.
- **Reviews and project manifests** are replayed through the new server's
  `reviews` and `project` routes. The new server checks each record again. A
  project manifest names its tenant, so it can only be imported into a tenant
  with the same name. `tenant import --repo` installs Reviews locally but not
  the project chain, because `tine project` keeps its own chain in the
  repository you run it in.
- **The transparency log does not move.** A log is the server's own signed
  history, and a new server starts its own log. The export keeps the old
  checkpoint and entries, so receipts the old server issued can still be
  checked offline against the old log key.
- **Share links do not move.** A share token is a capability minted by one
  server. The export lists the links so you can create them again with
  `tine share create` on the new server.
- **Server-side state does not move**: webhooks (their secrets stay with the
  server), coordination task leases (`caps.coord`), the server-keyed audit
  chain, admission VSAs, quotas, trust policies and identities. These are
  operator configuration, not tenant data. The new server's operator sets
  them up again.

## Byte-identical verification

`tine verify . --offline --json` in a repository checks every object against
its id (`fsck`) and reports each run a ref points at. The leave-the-service
test imports one export into a local repository and imports a second export,
taken from the new server, into another. Both repositories must give the same
report bytes, and the same per-run results as the repository the runs were
recorded in.
