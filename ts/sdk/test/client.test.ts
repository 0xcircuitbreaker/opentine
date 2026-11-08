import assert from "node:assert/strict";
import { test } from "node:test";

import { OPERATIONS, retryAfter, TineApiError, TineClient } from "../src/index.js";

type Seen = { url: string; init: RequestInit };

function fake(handler: (url: string, init: RequestInit) => Response): { fetch: typeof fetch; seen: Seen[] } {
  const seen: Seen[] = [];
  const impl = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input);
    seen.push({ url, init });
    return handler(url, init);
  }) as typeof fetch;
  return { fetch: impl, seen };
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

test("every operation's path is a /v1 path", () => {
  for (const [id, op] of Object.entries(OPERATIONS)) assert.match(op.path, /^\/v1\//, id);
});

test("path parameters are percent-encoded and the bearer token is sent", async () => {
  const { fetch, seen } = fake(() => json(200, { updated: true }));
  const client = new TineClient({ baseUrl: "https://tine.example/", tenant: "ac me", token: "t0k", fetch });
  assert.equal(await client.updateRef("heads/main", { new: "run:sha256:" + "a".repeat(64) }), true);
  assert.equal(seen[0].url, "https://tine.example/v1/tenants/ac%20me/refs/heads%2Fmain");
  assert.equal(seen[0].init.method, "PUT");
  assert.equal((seen[0].init.headers as Record<string, string>).authorization, "Bearer t0k");
});

test("a failed compare-and-swap is false, not an error", async () => {
  const { fetch } = fake(() => json(409, { updated: false }));
  const client = new TineClient({ baseUrl: "https://t", tenant: "a", fetch });
  assert.equal(await client.updateRefs([{ name: "heads/x", new: "run:sha256:" + "b".repeat(64) }]), false);
});

test("errors carry the status, the body and Retry-After", async () => {
  const { fetch } = fake((url) =>
    url.endsWith("/refs") ? json(429, { error: "quota exceeded" }, { "retry-after": "7" }) : json(404, { error: "not found" }),
  );
  const client = new TineClient({ baseUrl: "https://t", tenant: "a", fetch });
  await assert.rejects(client.listRefs(), (error: unknown) => {
    assert.ok(error instanceof TineApiError);
    assert.equal(error.status, 429);
    assert.equal(error.retryAfter, 7);
    return true;
  });
  await assert.rejects(client.readObject("run:sha256:" + "c".repeat(64)), (error: unknown) => {
    assert.ok(error instanceof TineApiError);
    assert.deepEqual([error.status, error.body], [404, { error: "not found" }]);
    return true;
  });
});

test("listRuns sends its query and capabilities need no token", async () => {
  const { fetch, seen } = fake(() => json(200, { runs: [], next_cursor: null }));
  const client = new TineClient({ baseUrl: "https://t", tenant: "a", fetch });
  await client.listRuns("c1", 5);
  assert.equal(seen[0].url, "https://t/v1/tenants/a/runs?cursor=c1&limit=5");
  await client.capabilities();
  assert.equal((seen[1].init.headers as Record<string, string>).authorization, undefined);
});

test("events parses Server-Sent Events frames, skipping comments and retry hints", async () => {
  const text =
    "retry: 2000\n\n: heartbeat\n\n" +
    'id: 1\nevent: ref.updated\ndata: {"id":"1","kind":"ref.updated"}\n\n' +
    "event: reset\ndata: {}\n\n";
  const encoded = new TextEncoder().encode(text);
  const { fetch, seen } = fake(
    () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(encoded.subarray(0, 30));
            controller.enqueue(encoded.subarray(30));
            controller.close();
          },
        }),
        { status: 200, headers: { "content-type": "text/event-stream" } },
      ),
  );
  const client = new TineClient({ baseUrl: "https://t", tenant: "a", token: "x", fetch });
  const events = [];
  for await (const event of client.events("0")) events.push(event);
  assert.deepEqual(events, [
    { id: "1", kind: "ref.updated", data: { id: "1", kind: "ref.updated" } },
    { id: "", kind: "reset", data: {} },
  ]);
  assert.equal((seen[0].init.headers as Record<string, string>)["last-event-id"], "0");
});

test("dot-segment parameters are refused and redirects are never followed", async () => {
  const { fetch, seen } = fake(() => json(200, { updated: true }));
  const client = new TineClient({ baseUrl: "https://t", tenant: "a", token: "x", fetch });
  assert.throws(() => client.url("updateRef", { ref: ".." }), TypeError);
  assert.throws(() => new TineClient({ baseUrl: "https://t", tenant: ".", fetch }).url("listRefs"), TypeError);
  await client.updateRef("heads/main", { new: "run:sha256:" + "a".repeat(64) });
  assert.equal(seen[0].init.redirect, "error");
});

test("Retry-After accepts delta-seconds and HTTP-dates", () => {
  assert.equal(retryAfter("12"), 12);
  assert.equal(retryAfter("Thu, 01 Jan 1970 00:00:30 GMT", 0), 30);
  assert.equal(retryAfter("soon"), null);
  assert.equal(retryAfter(null), null);
});

test("multi-line SSE data and CRLF framing", async () => {
  const text = 'id: 2\r\nevent: x\r\ndata: {"a":\r\ndata: 1}\r\n\r\n';
  const { fetch } = fake(() => new Response(text, { status: 200, headers: { "content-type": "text/event-stream" } }));
  const events = [];
  for await (const event of new TineClient({ baseUrl: "https://t", tenant: "a", fetch }).events()) events.push(event);
  assert.deepEqual(events, [{ id: "2", kind: "x", data: { a: 1 } }]);
});
