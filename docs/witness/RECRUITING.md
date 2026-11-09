# Become an independent OpenTine witness

OpenTine's hosted logs require cosignatures from 2 of 3 independent witnesses
before a checkpoint counts. The project runs one witness; we are looking for
at least two more operators who are independent of the project and of each
other. A witness never sees run contents — only log checkpoints (an origin, a
tree size and a hash) — and its whole job is to refuse to cosign two
inconsistent histories.

## Who we are looking for

- Organisations with an interest in verifiable AI-agent records: universities,
  research institutes, foundations, other transparency-log operators, CI or
  supply-chain security vendors.
- Able to run a small always-on service with an on-call contact, and to keep a
  key ceremony record (`OPERATING.md` §3).
- Independent: not employed by, funded by or hosted on the same account as the
  OpenTine project or another witness. A different cloud provider and
  jurisdiction from the other witnesses is preferred.

## What it takes

- One small VM or container (1 vCPU, 512 MiB), durable storage, an HTTPS
  name. Cost is typically a few dollars a month.
- An HSM/KMS key, or an encrypted key file with offline backups.
- Monitoring of `GET /health` and a daily `tine witness doctor`.
- Best-effort availability: 2-of-3 tolerates one witness down, so short
  outages are fine; tell the log operator about planned maintenance.
- 30 days' notice before leaving.

## What we commit to

- Publishing the registry with your operator name, URL and contact (and
  jurisdiction, if you wish) and acknowledging you in the release notes.
- Notifying all operators of registry changes at least one refresh period
  (30 days) before a key is dropped.
- A public incident process: any split view a witness refuses is published.
- No access to your infrastructure, ever. We never hold your key.

## How to join

1. Read `OPERATING.md` and deploy from `deploy/witness/` (or your own build of
   `tine witness serve`).
2. Run the key ceremony and `tine witness doctor` against the test registry we
   send you.
3. Open an issue titled "Witness operator: <your org>" with your witness name,
   URL, vkey, contact and jurisdiction, and confirm the vkey over a second
   channel (signed email to the maintainers listed in `SECURITY.md`).
4. We add you to the staging registry, watch two weeks of healthy cosigning,
   then to the production registry in the next release.

## Status

Recruitment has not started yet: this document and the operator kit are
ready, and the outreach is outstanding for the maintainers (see `OPERATING.md`).
