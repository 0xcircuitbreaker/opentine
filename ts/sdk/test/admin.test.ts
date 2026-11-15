import assert from "node:assert/strict";
import { test } from "node:test";

import { OPERATIONS, TineAdmin, TineApiError, TineClient } from "../src/index.js";

type Seen = { url: string; init: RequestInit };

function fake(handler: (url: string, init: RequestInit) => Response): { fetch: typeof fetch; seen: Seen[] } {
  const seen: Seen[] = [];
  const impl = (async (input: string | URL | Request, init: RequestInit = {}) => {
    seen.push({ url: String(input), init });
    return handler(String(input), init);
  }) as typeof fetch;
  return { fetch: impl, seen };
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const auth = (seen: Seen) => (seen.init.headers as Record<string, string>).authorization;

test("the admin operations are the 0.52 surface", () => {
  for (const id of ["getSession", "passkeyLogin", "createTenant", "setMember", "addHold"] as const) {
    assert.ok(OPERATIONS[id].cap === "session" || OPERATIONS[id].cap === "tenancy", id);
  }
});

test("login ceremonies never send the client's bearer token", async () => {
  const opened = { token: "tine_sess_x", subject: "user:1", method: "passkey", expires_at: 1 };
  const { fetch, seen } = fake(() => json(201, opened));
  const admin = new TineAdmin(new TineClient({ baseUrl: "https://t", tenant: "acme", token: "old", fetch }));
  const assertion = { challenge: "c", credential_id: "i", clientDataJSON: "d", authenticatorData: "a", signature: "s" };
  assert.deepEqual(await admin.passkeyLogin(assertion), opened);
  assert.equal(seen[0].url, "https://t/v1/auth/passkey/assertion");
  assert.equal(auth(seen[0]), undefined);
});

test("tenant routes take the client's tenant or an explicit one, percent-encoded", async () => {
  const { fetch, seen } = fake(() => json(200, { members: [{ subject: "a b", role: "writer" }] }));
  const admin = new TineAdmin(new TineClient({ baseUrl: "https://t", tenant: "acme", token: "tine_sess_y", fetch }));
  const members = await admin.setMember("a b", "writer", "beta");
  assert.deepEqual(members, [{ subject: "a b", role: "writer" }]);
  assert.equal(seen[0].url, "https://t/v1/tenants/beta/members/a%20b");
  assert.equal(seen[0].init.method, "PUT");
  assert.equal(auth(seen[0]), "Bearer tine_sess_y");
  await admin.listHolds();
  assert.equal(seen[1].url, "https://t/v1/tenants/acme/holds");
});

test("admin errors carry the uniform code", async () => {
  const { fetch } = fake(() => json(409, { error: "a tenant keeps at least one admin", code: "member.last_admin" }));
  const admin = new TineAdmin(new TineClient({ baseUrl: "https://t", tenant: "acme", token: "x", fetch }));
  await assert.rejects(admin.removeMember("root"), (error: unknown) => {
    assert.ok(error instanceof TineApiError);
    assert.equal(error.status, 409);
    assert.deepEqual(error.body, { error: "a tenant keeps at least one admin", code: "member.last_admin" });
    return true;
  });
});
