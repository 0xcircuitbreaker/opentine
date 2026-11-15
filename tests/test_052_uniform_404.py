"""0.52: the uniform-404 oracle over every route in the ``tine serve`` route table.

For each route a caller who may not read the target asks for four things: a
**private** object (it exists in another tenant), a **nonexistent** one (no
such tenant or id), an **archived** one (it existed and was retired: a revoked
share, a removed webhook, a finished task) and one **out of
scope** (in the caller's own tenant, but the token's roles grant nothing
there). All four must answer byte for byte alike: status, the headers that
could tell them apart, and body. A route added to ``ROUTES`` without an entry
in ``CASES`` fails :func:`test_every_route_has_oracle_coverage`.
"""

from __future__ import annotations

import io
import json
from itertools import count
from pathlib import Path

import pytest

from opentine import Run
from opentine.graph import StepKind
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.remote._api_routes import ROUTES
from opentine.repository import Repo

GHOST_OID = "run:sha256:" + "0" * 64
#: Headers that may differ between two identical refusals (none today).
IGNORED_HEADERS: frozenset[str] = frozenset()
#: Routes that are not about any object: nothing to hide.
EXEMPT = {"getCapabilities"}
#: operation -> request body that gets the route past parsing to authorization.
BODIES = {
    "updateRef": lambda ids: {"new": ids["oid"], "expected_old": None},
    "updateRefs": lambda ids: {
        "updates": [{"name": "heads/one", "new": ids["oid"], "expected_old": None}]
    },
    "negotiate": lambda ids: {"wants": [ids["oid"]]},
    "fetchPack": lambda ids: {"wants": [ids["oid"]]},
    "uploadPack": lambda ids: {"sha256": "0" * 64, "size": 10},
    "search": lambda ids: {"type": "run"},
    "addWebhook": lambda ids: {"url": "https://hooks.example.com/x"},
    "createShare": lambda ids: {"run": ids["oid"]},
    "putTombstone": lambda ids: {"kind": "opentine.tombstone"},
    "updateProject": lambda ids: {"expected_old": None, "version": {"kind": "opentine.project"}},
    "updateReview": lambda ids: {"expected_old": None, "version": {"kind": "opentine.review"}},
    "decideReviewGate": lambda ids: {"decision": {"kind": "opentine.review-gate"}},
    "addTask": lambda ids: {"task": ids["task"]},
    "runClosure": lambda ids: {},
    "sharedClosure": lambda ids: {},
    **{op: (lambda ids: {"holder": "h", "fencing": 1})
       for op in ("claimTask", "heartbeatTask", "finishTask")},
}  # fmt: skip
#: Every route the oracle covers; the value names the population it needs.
CASES = {route.operation: "tenant" for route in ROUTES if "{tenant}" in route.path}
CASES |= {"getSharedRun": "share", "sharedClosure": "share", "readSharedObject": "share"}


def _identities() -> StaticTokenIdentityProvider:
    return StaticTokenIdentityProvider(
        {
            "acme-admin": Identity("root", "acme", ("admin",)),
            "eve-admin": Identity("eve", "other", ("admin",)),
            "acme-guest": Identity("gus", "acme", ("guest",)),  # in acme, no grant at all
        }
    )


_addr = count(1)


def _call(app, method, path, body=None, token=None):
    raw = json.dumps(body).encode() if body is not None else b""
    state: dict = {}

    def start(status, headers):
        state["status"], state["headers"] = status, dict(headers)

    environ = {
        "CONTENT_LENGTH": str(len(raw)),
        "CONTENT_TYPE": "application/json",
        "HTTP_UPLOAD_OFFSET": "0",
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "REMOTE_ADDR": f"10.9.{next(_addr) % 250}.{next(_addr) % 250}",  # no share throttle
        "REQUEST_METHOD": method,
        "wsgi.input": io.BytesIO(raw),
    }
    if token:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    out = b"".join(app(environ, start))
    headers = {k: v for k, v in state["headers"].items() if k not in IGNORED_HEADERS}
    return state["status"], headers, out


def _ok(response, *statuses):
    assert response[0].split()[0] in statuses, response
    return json.loads(response[2]) if response[2] else {}


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    tmp = Path(tmp_path_factory.mktemp("oracle"))
    app = server.reference_app(
        tmp / "remote", identities=_identities(), keys=LocalKeyProvider(b"k" * 32)
    )
    local = Repo.init(tmp / "local")
    oids = []
    for label in ("one", "two"):
        run = Run(id=label, metadata={"label": label})
        run.add_step(StepKind.done, {"text": label * 50})
        oids.append(local.put_run(run).run_id)
    oid, outside = oids
    admin = app.service.authenticate({"authorization": "Bearer acme-admin"})
    app.service.install_pack(admin, "acme", local.pack())
    assert app.service.update_ref(admin, "acme", "heads/one", oid, None)
    t = "/v1/tenants/acme"

    def post(path, body, *ok):
        return _ok(_call(app, "POST", t + path, body, "acme-admin"), *(ok or ("201",)))

    share, old = post("/shares", {"run": oid}), post("/shares", {"run": oid})
    _ok(_call(app, "DELETE", f"{t}/shares/{old['id']}", None, "acme-admin"), "200")
    hook, gone = (post("/webhooks", {"url": f"https://hooks.example.com/{n}"}) for n in "ab")
    _ok(_call(app, "DELETE", f"{t}/webhooks/{gone['id']}", None, "acme-admin"), "200")
    post("/coord/tasks", {"task": "live"})
    post("/coord/tasks", {"task": "done"})
    lease = post("/coord/tasks/done/claim", {"holder": "h"}, "200")["task"]
    post("/coord/tasks/done/done", {"holder": "h", "fencing": lease["fencing"]}, "200")
    upload = post("/packs", {"sha256": "0" * 64, "size": 10})
    base = {"oid": oid, "ref": "heads%2Fone", "review_id": "auth-rework", "task": "live"}
    private = {**base, "tenant": "acme", "share_id": share["id"], "token": share["token"],
               "webhook_id": hook["id"], "upload_id": upload["upload_id"],
               "outside": outside}  # fmt: skip
    missing = {"tenant": "ghost", "oid": GHOST_OID, "ref": "heads%2Fnone", "share_id": "s_none",
               "token": "tine_share_" + "A" * 43, "webhook_id": "wh_none",
               "upload_id": "1" * 32, "review_id": "no-such-review", "task": "none"}  # fmt: skip
    archived = {**private, "share_id": old["id"], "token": old["token"],
                "webhook_id": gone["id"], "task": "done"}  # fmt: skip
    return app, {"private": private, "nonexistent": missing, "archived": archived}


def _variants(route, ids):
    """``{case: (method, path, body, token)}`` for one route."""
    body = BODIES.get(route.operation)
    out = {}
    for case, values in ids.items():
        token = None if route.permission is None else "eve-admin"
        out[case] = (route.method, "/v1" + route.path.format(**values),
                     body(values) if body else None, token)  # fmt: skip
    if route.path.startswith("/share/"):
        # A live token is the capability itself: only an object outside its
        # closure is private to it.
        if route.operation == "readSharedObject":
            values = {**ids["private"], "oid": ids["private"]["outside"]}
            out["private"] = (route.method, "/v1" + route.path.format(**values), None, None)
        else:
            del out["private"]
    if route.permission is not None:
        method, path, payload, _ = out["private"]
        out["out-of-scope"] = (method, path, payload, "acme-guest")
    return out


def test_every_route_has_oracle_coverage():
    uncovered = {r.operation for r in ROUTES} - set(CASES) - EXEMPT
    assert not uncovered, f"add these routes to the uniform-404 oracle: {sorted(uncovered)}"
    assert all("{tenant}" in r.path or r.path.startswith("/share/") or r.operation in EXEMPT
               for r in ROUTES)  # fmt: skip


@pytest.mark.parametrize("route", [r for r in ROUTES if r.operation in CASES],
                         ids=lambda r: r.operation)  # fmt: skip
def test_private_missing_archived_and_out_of_scope_look_identical(world, route):
    app, ids = world
    answers = {case: _call(app, *call) for case, call in _variants(route, ids).items()}
    first = answers["nonexistent"]
    assert first[0] == "404 Not Found" and json.loads(first[2]) == {"error": "not found"}, first
    for case, answer in answers.items():
        assert answer == first, (route.operation, case, answer, first)


def test_an_object_of_another_tenant_is_a_uniform_404_to_a_reader_of_this_one(world):
    app, ids = world
    for path in ("/objects/{oid}", "/tombstones/{oid}", "/coord/tasks/{task}"):
        seen = path.format(oid=ids["private"]["oid"], task="live")
        unseen = path.format(oid=GHOST_OID, task="none")
        here = _call(app, "GET", "/v1/tenants/other" + seen, None, "eve-admin")
        absent = _call(app, "GET", "/v1/tenants/other" + unseen, None, "eve-admin")
        assert here == absent and here[0] == "404 Not Found", (path, here, absent)
