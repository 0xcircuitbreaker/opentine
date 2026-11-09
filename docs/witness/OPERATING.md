# Operating an OpenTine witness

This is the production runbook for a witness in the OpenTine trust network:
the project's public witness and every independent operator follow it. A
witness cosigns a transparency-log checkpoint only when it is consistent with
the last checkpoint it cosigned for that log (SPEC §8.10, §8.23). A hosted log
requires a quorum of its witnesses (2-of-3) to cosign, so no single party — the
log operator included — can show two users two different histories.

> **Status (0.49).** The software, this runbook, the container definition
> (`deploy/witness/`), the registry format (`NETWORK.md`) and `tine witness
> doctor` are shipped and tested with three local witness processes
> (`tests/test_049_witness_network.py`). **Outstanding, for humans:** standing
> up the project's public witness on real infrastructure, running the key
> ceremony below, recruiting at least two independent operators
> (`RECRUITING.md`), publishing the signed production registry, and pinning
> the published image by digest. None of that can be done from a CI sandbox,
> and nothing in this repository claims it has happened.

## 1. What a witness holds

| Item | Secret? | Where |
| --- | --- | --- |
| Ed25519 witness key(s) | **yes** | HSM/KMS signer URI, or an encrypted PKCS#8 file mounted read-only at `/run/secrets/witness-*.key` |
| Witness name (e.g. `witness.example.org`) | no | `WITNESS_NAME`; it is part of every cosignature |
| Pinned log vkeys | no | `WITNESS_LOG_VKEYS`, copied from the hosted log's registry |
| State: last checkpoint cosigned per log | no, but **integrity-critical** | the volume at `/var/lib/witness` |

Losing the state is a safety incident, not an inconvenience: a witness that
forgets what it cosigned can be tricked into cosigning a fork. Back it up, and
never restore a backup older than the newest cosignature without the
procedure in §7.

## 2. Hardware and hosting

- **Compute:** 1 vCPU, 512 MiB RAM is ample; a cosignature is one Ed25519
  signature and an O(log n) consistency proof check.
- **Disk:** a few MiB of state per log; use durable, snapshotted storage
  (a replicated block volume, not instance-local scratch).
- **Network:** an HTTPS endpoint (TLS terminated by a reverse proxy or load
  balancer in front of port 8080). Only `POST /add-checkpoint`, `GET /health`
  and `GET /keys` need to be public.
- **Isolation:** a dedicated VM or container host that runs nothing else, in
  an account the log operator has no access to. Independence is the point:
  pick a provider and a jurisdiction different from the log's and from the
  other witnesses' where you can (record them in the registry's
  `jurisdiction` field).
- **Keys:** prefer an HSM or cloud KMS (`tine witness serve --key
  pkcs11:...` or `kms:aws:ARN`, the 0.41 signer backends; build the image with `opentine[pkcs11]` or `opentine[kms-aws]`) so the private key is
  never on disk. A passphrase-encrypted PKCS#8 file is the minimum.
- **Clock:** NTP-synchronised; cosignatures carry a timestamp.

## 3. Key ceremony

Perform it with two people present (an operator and a witness), on an
offline machine for file keys or from an administrative workstation for KMS
keys, and keep a signed written record.

1. Choose the witness name. It must be stable for the life of the witness;
   use a DNS name you control.
2. Generate the key: `tine keygen` into an encrypted PKCS#8 file, or create
   an Ed25519 key in the HSM/KMS (non-exportable, sign-only policy).
3. Print the verifier key: `tine witness vkey --key KEY --name NAME`.
4. Both people read the vkey aloud and compare it against the screen of a
   second machine; record it, the date and both signatures in the ceremony
   log.
5. Back up file keys to two offline media in separate locations, each
   encrypted with a different custodian's passphrase. KMS keys: enable
   deletion protection.
6. Send the vkey, name, URL, operator name, contact and jurisdiction to the
   log operator over two independent channels (e.g. a signed email and a
   pull request to the registry repository). The log operator confirms the
   vkey out of band before adding it to the registry.

## 4. Deploy

```sh
docker build -f deploy/witness/Containerfile -t opentine-witness:0.48.0 deploy/witness
cp deploy/witness/witness.env.example witness.env   # edit: name and log vkeys
docker run -d --name witness --restart unless-stopped \
  --env-file witness.env \
  -v witness-state:/var/lib/witness \
  -v /secure/witness-1.key:/run/secrets/witness-1.key:ro \
  -p 127.0.0.1:8080:8080 opentine-witness:0.48.0
```

Put the TLS proxy in front of `127.0.0.1:8080`. Before announcing the
witness, run the doctor from the host with the same inputs plus the public
URL and the registry:

```sh
tine witness doctor --key /secure/witness-1.key --name witness.example.org \
  --log-vkey "$LOG_VKEY" --state /var/lib/docker/volumes/witness-state/_data/witness \
  --registry network.json --url https://witness.example.org --json
```

It exits 4 and names each failing check (`keys`, `key-files`, `state`,
`logs`, `registry`, `health`, `keys-served`, `url`); its output never names a
key path. Run it after every deploy and from monitoring.

## 5. Rotation

A witness may hold several keys under one name; each cosigns, the first is
current (SPEC §8.23). To rotate:

1. Run the ceremony (§3) for the new key.
2. Mount it as the *second* key (`witness-2-<date>.key`) and restart; `GET
   /keys` now lists both, current first. The registry entry lists both vkeys.
3. Wait until the new registry has been published and the verifiers you
   know of (hosted log, monitors, CI pins) have picked it up — at least one
   registry refresh period, 30 days by default.
4. Swap the order (new key first), restart, then remove the old key from the
   registry and the mount at the next refresh. Destroy the old key per your
   policy and log it in the ceremony record.

Never drop the old key before verifiers pin the new one: a checkpoint carrying
only an unpinned cosignature counts for nobody.

## 6. Monitoring

- **Liveness:** `GET /health` every minute from outside your network; alert
  on non-200 for 5 minutes. `503 degraded` means the state cannot be read or
  written: page immediately.
- **Progress:** `/health` reports `logs: {origin: size}`; alert if a log's
  size has not advanced for longer than the log's publishing interval.
- **Refusals:** `/health` `requests` counts outcomes by status. A rising
  `422` count is a fork or rollback attempt (§7); `403` is a bad log
  signature; `429` is rate limiting.
- **Keys:** a daily `tine witness doctor ... --registry --url` catches a
  served key set that drifted from the registry.
- **Certificates and disk:** TLS expiry ≥ 14 days, volume free space.

## 7. Incident response

| Incident | Action |
| --- | --- |
| `422` from a log (fork or rollback) | Do **not** clear state. Preserve both checkpoints (the stored one and the rejected request body), notify the log operator and the other witnesses' contacts, and file a public report: a split view is the event the network exists to expose. |
| Key compromise suspected | Stop the witness. Notify the log operator to remove the vkey from the registry immediately (2-of-3 tolerates one witness down). Run a new ceremony with a new key, publish the incident and the compromise window. |
| State lost or corrupted | Stop the witness; `/health` reports `degraded`. Restore the latest backup, then fetch the log's current checkpoint and verify it is consistent with the restored one (`tine witness cosign --tiles`) before serving. If consistency cannot be shown, rejoin as a new witness name. |
| Host lost | Redeploy from the container definition with the backed-up state and key; run the doctor before re-enabling the endpoint. |
| Prolonged outage | Tell the log operator; with one witness down a 2-of-3 log still publishes, with two down it stops cosigning, which is the safe failure. |

Record every incident with timestamps in an append-only log you can publish.

## 8. Leaving the network

Give the log operator 30 days' notice so a replacement can be recruited and the
registry updated before your endpoint goes away. Keep the state and the key
record for one year afterwards, so past cosignatures can be audited.
