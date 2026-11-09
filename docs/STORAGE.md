# Object storage for `tine serve`: S3 Object Lock and Azure immutable blobs

By default `tine serve` keeps objects as sealed files under `<root>/objects`.
From 0.49 it can keep them in write-once (WORM) object storage instead, with a
retention period the cloud enforces. Refs, the audit chain and other metadata
stay in `<root>/metadata.sqlite3`, as before.

## Configuration

All settings are environment variables read when the server starts.

| Variable | Meaning |
|---|---|
| `TINE_REMOTE_OBJECT_STORE` | `s3://<bucket>[/<prefix>]` or `azblob://<container>[/<prefix>]`. Unset: the filesystem store. |
| `TINE_REMOTE_RETENTION_MODE` | `governance` or `compliance`. Unset: no retention date (legal holds still work). |
| `TINE_REMOTE_RETENTION_DAYS` | Retention for every new object, in days (1 to 36500). Required with a mode. |
| `TINE_REMOTE_S3_ENDPOINT` | An S3-compatible endpoint, such as MinIO (`http://127.0.0.1:9000`). |
| `AZURE_STORAGE_CONNECTION_STRING` | The Azure account (or Azurite) for `azblob://`. |

S3 credentials and region come from boto3's usual chain (`AWS_*` variables,
profiles, instance roles). The S3 store needs `boto3`, and the Azure store
needs `azure-storage-blob`.

```sh
export TINE_KMS_KEY=...                      # sealing key, as for the filesystem store
export TINE_REMOTE_OBJECT_STORE=s3://acme-tine/prod
export TINE_REMOTE_RETENTION_MODE=compliance
export TINE_REMOTE_RETENTION_DAYS=2555       # about 7 years
tine serve --root /var/lib/tine-remote --cert ... --key ...
```

### Preparing the bucket or container

* **S3:** create the bucket with Object Lock enabled
  (`aws s3api create-bucket --bucket acme-tine --object-lock-enabled-for-bucket`).
  Object Lock cannot be turned on later for an existing bucket without AWS
  support. The server's role needs `s3:PutObject`, `s3:GetObject`,
  `s3:ListBucket`, `s3:DeleteObject`, `s3:DeleteObjectVersion`,
  `s3:GetObjectRetention`, `s3:PutObjectRetention`, `s3:GetObjectLegalHold`
  and `s3:PutObjectLegalHold`. Do **not** grant it
  `s3:BypassGovernanceRetention`.
* **MinIO:** `minio server --address :9000 /data`, then create the bucket with
  `mc mb --with-lock local/acme-tine` (or boto3's `ObjectLockEnabledForBucket`).
* **Azure:** create the container with version-level immutability support.
  Azurite accepts the same calls for development.

## Retention modes

| OpenTine | S3 Object Lock | Azure | Who can shorten it |
|---|---|---|---|
| `governance` | `GOVERNANCE` | `Unlocked` immutability policy | an operator with the bypass permission, outside OpenTine |
| `compliance` | `COMPLIANCE` | `Locked` immutability policy | no one, the root account included |
| hold (`tine hold`) | legal hold `ON` | legal hold | whoever can clear the hold |

The retention date is set when an object is first written and is not extended
when the same object is pushed again.

## Deletes

A delete (for example a tombstone purge) is refused, with a
`PermissionError`, when any of these holds:

1. the object is held in the OpenTine holds file (`<root>/objects/.holds/<tenant>`);
2. the configured retention policy says to keep it;
3. the cloud reports a retention date in the future, or a legal hold.

If OpenTine's checks pass but the cloud still refuses, that refusal is
reported the same way. OpenTine never sends `BypassGovernanceRetention`. On
S3 a delete names the current version, so the bytes go away rather than being
hidden behind a delete marker.

## Holds

OpenTine holds map to legal holds: `WormObjectStore.sync_holds(tenant)` places a
legal hold on every held object (and on each of its chunks), so the hold
stands even against someone who reaches the bucket without OpenTine. With
`release=True` it also clears legal holds on objects that are no longer held
(this reads every object's retention, so run it as an operator step).

## Large payloads: FastCDC chunks and lazy fetch

Payloads of 8 MiB or more are stored as content-defined chunks (normalized
FastCDC; min 256 KiB, average 1 MiB, max 4 MiB) plus a chunk manifest. This is
a stored form, not a new object kind: the oid still names the envelope bytes.

```
<prefix>/<tenant>/objects/<type>/<digest>   sealed object, or "TINECDCM" + sealed manifest
<prefix>/<tenant>/chunks/<sha256>           a sealed chunk, shared by every object in the tenant
<prefix>/<tenant>/chunked/<type>/<digest>   empty marker naming chunked objects
```

The manifest is `TINECDC1`, the total size (u64), the chunk count (u32) and,
for each chunk, its SHA-256 and size (u32), all big-endian. Readers fetch
only the chunks a range needs, check each chunk's SHA-256, and `get`
re-hashes the joined envelope against its oid. A grown transcript shares its
earlier chunks with the previous version. Deleting a chunked object deletes
its chunks that no other object uses; a chunk still inside retention stays
until its date passes. Numbers are in `docs/bench/0.49-fastcdc-store.md`.

Chunk names are plaintext SHA-256 digests, so someone who can list the bucket
learns when two objects in a tenant share a chunk. The chunk bytes are sealed.

## Testing against real services

`tests/test_049_worm_integration.py` runs the same scenario (write, read, a
lazy range read, refused deletes, legal hold) against each service that is
available, and skips the others with the reason:

* moto (installed with the `dev` extra): in-process S3 with Object Lock;
* MinIO: `TINE_TEST_MINIO_ENDPOINT` plus `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`
  (`docker run -p 9000:9000 minio/minio server /data`);
* AWS: `TINE_TEST_S3_BUCKET`, an existing bucket with Object Lock on;
* Azurite or Azure: `TINE_TEST_AZURE_CONNECTION` and `TINE_TEST_AZURE_CONTAINER`.
