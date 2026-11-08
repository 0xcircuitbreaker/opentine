# Events, `tine watch` and signed webhooks (0.45.1)

`tine serve` reports what happens in each tenant three ways: a Server-Sent
Events stream, `tine watch`, and webhooks whose payloads are signed with an
Ed25519 key the server advertises. All three carry the same `tine-event/1`
objects ([schema](schemas/tine-event-1.schema.json)).

## Events

| `kind` | When | `data` |
|---|---|---|
| `ref.updated` | `PUT refs/...` or a ref transaction moved a ref | `name`, `old` (the expected old value the writer sent, or null), `new`, `forced` |
| `run.created` | an installed pack carried runs | `runs` (at most 100 run oids), `total` |
| `log.checkpoint` | the audit transparency log grew | `origin`, `size`, `root` (base64) |
| `op.logged` | `tine watch` on a local repository only: an op-log entry | the `opentine-op/1` entry |

An event's `id` is `<epoch>-<seq>`; `epoch` changes when the server restarts.

## `GET /v1/tenants/<tenant>/events`

Needs `read_ref` in the tenant (the permission that lists refs). The response is
`text/event-stream`: one `id:`/`event:`/`data:` frame per event, a
`: heartbeat` comment every 10 s, and the stream closes after 25 s (inside the
server's request deadline) so the client reconnects with `Last-Event-ID`. The
server keeps the last 1024 events per tenant; a `Last-Event-ID` from another
server process, or older than the buffer, gets an `event: reset` frame first:
re-list refs, then carry on. At most four streams are open at once; a fifth
gets `503` with `Retry-After`. Advertised as `caps.events_sse`.

## `tine watch [REMOTE|REPO]`

```
tine watch origin                       # a configured remote: tenant and token file from config
tine watch https://tine.example/v1/tenants/acme --token-file ~/.tine-token
tine watch                              # the op log of the repository here, polled every 2 s
tine watch ../other-repo --from-start --once --json
```

`--json` writes one `tine-watch/1` object per line (JSON Lines): `{"command":
"watch", "schema": "tine-watch/1", "event": {...}}`, or `"reset": true`.
`--max-events N` exits after N events; `--once` after one stream or one poll.

## Webhooks

Admins register targets per tenant (at most 16):

```
POST   /v1/tenants/<tenant>/webhooks       {"url": "https://hooks.example/tine", "kinds": ["ref.updated"]}
GET    /v1/tenants/<tenant>/webhooks       registrations and the last delivery outcomes
DELETE /v1/tenants/<tenant>/webhooks/<id>
```

`kinds` defaults to all three remote kinds. Each delivery is a `POST` of a
`tine-webhook/1` body ([schema](schemas/tine-webhook-1.schema.json)):
`{"format": "tine-webhook/1", "delivery": "<uuid>", "webhook": "<id>", "event":
{...}}`, canonical JSON (sorted keys, no whitespace, ASCII). Headers:

* `OpenTine-Signature: t=<unix seconds>,kid=<key id>,sig=<base64url Ed25519 signature>`
  over `opentine-webhook/1\n<t>\n<body>`;
* `OpenTine-Delivery: <uuid>`, the same on every retry (de-duplicate by it).

A 2xx answers a delivery. 408, 429, 5xx and connection errors are retried after
1, 2, 4 and 8 s (five attempts), re-signing `t` each time; any other status
gives up. Redirects are not followed.

**SSRF.** A target must be `https://` and every address its name resolves to
must be global: loopback, private, link-local (including cloud metadata),
CGNAT, multicast and reserved addresses are refused at registration and at
each delivery, and the delivery connects to the address it checked. For a
receiver on your own network, start the server with
`tine serve --webhooks-allow-private`, which also allows `http://`.

**Keys.** The server's webhook key is `<root>/webhook-ed25519.key`, created on
first start. Its public half is in `GET /v1/capabilities` under
`webhooks.keys`: `[{"kid": "ed25519:<16 hex>", "alg": "ed25519", "public_key":
"<base64url raw key>"}]`, where the key id is the first 16 hex digits of
SHA-256 over the raw key. Pin it once; do not fetch it per delivery.

## Verifying a delivery

Check the timestamp against a replay window (300 s), then the signature over
the exact bytes received. Both verifiers below are run by the test suite
against the conformance vectors in `docs/conformance/vectors/59-webhook.json`.

Python (needs `cryptography`):

<!-- verifier:python -->
```python
import base64, json, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_webhook(body: bytes, header: str, keys: dict, now=None, window=300) -> dict:
    """keys: key id -> base64url raw public key, from GET /v1/capabilities (webhooks.keys)."""
    fields = dict(part.split("=", 1) for part in header.split(","))
    t, kid, sig = fields["t"], fields["kid"], fields["sig"]
    if not t.isdigit() or abs((time.time() if now is None else now) - int(t)) > window:
        raise ValueError("stale or malformed timestamp")
    raw_key = base64.urlsafe_b64decode(keys[kid] + "=" * (-len(keys[kid]) % 4))
    signature = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    signed = b"opentine-webhook/1\n" + str(int(t)).encode() + b"\n" + body
    Ed25519PublicKey.from_public_bytes(raw_key).verify(signature, signed)  # raises if forged
    return json.loads(body)
```

JavaScript (Node 18+, no dependencies):

<!-- verifier:js -->
```js
const crypto = require("node:crypto");

function verifyWebhook(body, header, keys, now = Date.now() / 1000, windowS = 300) {
  // body: Buffer of the raw request body; keys: key id -> base64url raw public key
  const f = Object.fromEntries(header.split(",").map((p) => [p.slice(0, p.indexOf("=")), p.slice(p.indexOf("=") + 1)]));
  if (!/^[0-9]+$/.test(f.t) || Math.abs(now - Number(f.t)) > windowS) throw new Error("stale or malformed timestamp");
  if (!(f.kid in keys)) throw new Error("unknown webhook key");
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(keys[f.kid], "base64url")]);
  const key = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  const signed = Buffer.concat([Buffer.from(`opentine-webhook/1\n${Number(f.t)}\n`), body]);
  if (!crypto.verify(null, signed, key, Buffer.from(f.sig, "base64url"))) throw new Error("bad signature");
  return JSON.parse(body.toString("utf8"));
}

module.exports = { verifyWebhook };
```

Verify the raw body before parsing it: re-serializing the JSON changes the
bytes. Behind a proxy that rewrites bodies, verify where the bytes are intact.
