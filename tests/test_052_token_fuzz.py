"""0.52 token-scope fuzzer: no scoped token reaches outside its tenant, access or namespaces.

Seeded random requests over every route of the v1 table (no ``hypothesis``
dependency), each with a randomly scoped token, against invariants checked on
every reply and on the server's state after it:

- nothing answers 5xx;
- a 2xx on a tenant route is always for the token's own tenant;
- a read token never changes a ref, and no token mints, lists or revokes tokens;
- a namespace-limited token gets a 2xx only from the routes ``_token_scope``
  lists; a ref listing it gets holds only its refs; a fetch or negotiation it
  gets names only wants that its refs target; and no ref outside its
  namespaces, nor any ref of another tenant, ever changes.

The quick run is a few hundred requests. The 24 h human run sets
``TINE_TOKEN_FUZZ_SECONDS=86400`` (and optionally ``TINE_TOKEN_FUZZ_SEED``);
it prints the seed and request count so a failure can be replayed.
"""

from __future__ import annotations

import json
import os
import random
import time
from urllib.parse import quote

import pytest

from opentine.remote._api_routes import ROUTES
from opentine.remote._token_scope import in_namespace
from tests._auth_helpers import call, local_run, make_app, push

SCOPES = [["*"], ["heads/ci/"], ["heads/main"], ["heads/ci/", "tags/v1"], ["heads/ci"],
          ["promotions/"], ["heads/nothing/"]]  # fmt: skip
REFS = ["heads/main", "heads/ci/a", "heads/ci/b", "heads/ci", "heads/cix", "tags/v1",
        "promotions/prod", "heads/new", "heads/ci/new", "refs/heads/ci/c"]  # fmt: skip
#: Routes a namespace-limited token may get a 2xx from (``_token_scope``).
LIMITED_OK = {"getCapabilities", "listRefs", "updateRef", "updateRefs", "negotiate",
              "fetchPack", "uploadPack", "uploadOffset", "uploadChunk", "getLimits",
              "getAuthMethods"}  # fmt: skip
READ_ONLY_POSTS = {"negotiate", "fetchPack", "search", "runClosure", "sharedClosure"}
PUBLIC = {"getCapabilities", "getLimits", "getAuthMethods", "exchangeCiToken"}
PACK = "application/vnd.opentine.pack"
TENANTS = ("acme", "other")
#: Half the requests go to the routes a limited token may use, so they are exercised.
FOCUS = [route for route in ROUTES if route.operation in LIMITED_OK]


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fuzz")
    app = make_app(tmp / "remote")
    runs = {name: push(app, tmp, f"r{index}", name) for index, name in enumerate(REFS[:7])}
    admin = app.service.authenticate({"authorization": "Bearer other-token"})
    other_run, other_pack = local_run(tmp, "other")
    app.service.install_pack(admin, "other", other_pack)
    assert app.service.update_ref(admin, "other", "heads/main", other_run, None)
    extra = local_run(tmp, "extra")
    return app, list(runs.values()) + [other_run], extra


def _request(rng: random.Random, route, oids: list[str], extra, own: str, near: list[str]):
    tenant = own if rng.random() < 0.7 else rng.choice(["acme", "other", "Acme"])
    values = {"tenant": tenant, "ref": quote(rng.choice(REFS), safe=""),
              "oid": quote(rng.choice(oids + ["run:sha256:" + "e" * 64]), safe=""),
              "upload_id": "0" * 32, "webhook_id": "wh_x", "share_id": "s1",
              "token": "tine_share_" + "x" * 43, "review_id": "r1", "task": "t1",
              "token_id": "0" * 16}  # fmt: skip
    path = "/v1" + route.path.format(**values)
    pool = near if near and rng.random() < 0.5 else oids  # often the token's own targets
    wants = rng.sample(pool, min(len(pool), rng.randint(1, 2)))
    move = {"name": rng.choice(REFS), "new": rng.choice(oids), "expected_old": None}
    bodies = {
        "updateRef": {"new": rng.choice(oids), "expected_old": rng.choice([None, *oids]),
                      "force": rng.random() < 0.3},
        "updateRefs": {"updates": [move, {**move, "name": rng.choice(REFS)}][: rng.randint(1, 2)]},
        "negotiate": {"wants": wants, "haves": []},
        "fetchPack": {"wants": wants},
        "search": {"type": "run"},
        "runClosure": {},
        "createShare": {"run": rng.choice(oids)},
        "addWebhook": {"url": "https://hooks.example/x"},
        "addTask": {"task": "t1"},
        "mintToken": {"access": "write", "refs": ["*"]},
        "exchangeCiToken": {"token": "a.b.c"},
    }  # fmt: skip
    if route.operation == "uploadPack" and rng.random() < 0.7:
        return path, None, extra[1]
    return path, bodies.get(route.operation, {}), None


def _check(op, route, token_tenant, access, scope, path, status, body, before, after, oids_of):
    assert status < 500, (op, path, status, body)
    tenant = path.split("/")[3] if path.startswith("/v1/tenants/") else None
    ok = 200 <= status < 300
    if ok and tenant is not None:
        assert tenant == token_tenant, (op, path)
    assert after["tokens"] == before["tokens"], (op, path)  # no scoped token touches tokens
    for name in TENANTS:
        if name != token_tenant or access == "read":
            assert after[name] == before[name], (op, path, name)
    if access == "read" and ok and op not in PUBLIC:
        assert route.method in ("GET", "HEAD") or op in READ_ONLY_POSTS, (op, path)
    if scope == ["*"]:
        return
    limited = tuple(scope)
    if ok:
        assert op in LIMITED_OK, (op, path, status)
    own_before, own_after = before[token_tenant], after[token_tenant]
    for name in set(own_before) | set(own_after):
        if not in_namespace(limited, name):
            assert own_before.get(name) == own_after.get(name), (op, name)
    if ok and op == "listRefs":
        assert all(in_namespace(limited, name) for name in json.loads(body)["refs"])
    if ok and op in ("fetchPack", "negotiate"):
        targets = {oid for name, oid in own_before.items() if in_namespace(limited, name)}
        assert set(oids_of) <= targets, (op, oids_of)


def _state(app) -> dict:
    return {"acme": dict(app.service.index.list_refs("acme")),
            "other": dict(app.service.index.list_refs("other")),
            "tokens": len(app.tokens.list())}  # fmt: skip


def test_no_token_reaches_outside_its_scope(world):
    app, oids, extra = world
    seconds = float(os.environ.get("TINE_TOKEN_FUZZ_SECONDS") or 0)
    seed = int(os.environ.get("TINE_TOKEN_FUZZ_SEED") or 52)
    rng = random.Random(seed)
    deadline = time.monotonic() + seconds
    tokens = []
    for scope in SCOPES:
        for access in ("read", "write"):
            for tenant in ("acme", "other"):
                tokens.append((app.tokens.mint(tenant, access, scope, ttl=366 * 86400)[0],
                               tenant, access, scope))  # fmt: skip
    minted = len(app.tokens.list())
    count = 0
    successes: dict[str, int] = {}
    while count < 400 or time.monotonic() < deadline:
        secret, tenant, access, scope = rng.choice(tokens)
        route = rng.choice(FOCUS if rng.random() < 0.5 else ROUTES)
        refs = app.service.index.list_refs(tenant)
        near = sorted({o for n, o in refs.items() if scope == ["*"] or in_namespace(scope, n)})
        path, body, raw = _request(rng, route, oids, extra, tenant, near)
        before = _state(app)
        assert before["tokens"] == minted
        status, _, reply = call(app, route.method, path, body, secret, raw=raw,
                                content_type=PACK if raw else "application/json",
                                addr=f"10.9.{count % 200}.1")  # fmt: skip
        wants = (body or {}).get("wants", []) if isinstance(body, dict) else []
        _check(route.operation, route, tenant, access, scope, path, status, reply, before,
               _state(app), wants)  # fmt: skip
        count += 1
        if 200 <= status < 300 and scope != ["*"]:
            successes[route.operation] = successes.get(route.operation, 0) + 1
    print(f"token fuzz: seed={seed} requests={count} limited 2xx={sorted(successes.items())}")
    # The run must exercise the scoped routes, not only refusals.
    assert {"listRefs", "fetchPack"} <= set(successes), successes
