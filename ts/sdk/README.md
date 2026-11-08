# @opentine/sdk

A typed TypeScript client for the OpenTine remote API v1
([`docs/api/openapi-v1.yaml`](../../docs/api/openapi-v1.yaml)), the API of
`tine serve` and the hosted service. The client needs nothing but `fetch`
(Node 20.19+, browsers, workers).

```ts
import { TineClient } from "@opentine/sdk";
import { fetchVerified } from "@opentine/sdk/verified";

const client = new TineClient({ baseUrl: "https://tine.example", tenant: "acme", token });
const refs = await client.listRefs();
const objects = await fetchVerified(client, { wants: [refs["heads/main"]] });
```

`@opentine/sdk/verified` checks every byte it returns with the TS verifier
([`@opentine/verify`](../verifier), an optional peer dependency): pack
contents are re-hashed object by object and must include what was asked for,
a read object must hash to its oid, and webhook deliveries are checked against
the keys the remote advertises. A server can withhold objects; it cannot hand
back altered ones unnoticed.

Operations whose `OPERATIONS[id].status` is `planned` exist only on servers
that advertise `OPERATIONS[id].cap` in `GET /v1/capabilities`; elsewhere they
fail with a uniform `404` (`TineApiError`).

## Develop

```sh
npm --prefix ../verifier ci && npm --prefix ../verifier run build
npm ci && npm test && npm audit
```

`tests/test_api_v1_openapi.py` (Python) fails when `src/operations.ts` and the
OpenAPI document disagree.
