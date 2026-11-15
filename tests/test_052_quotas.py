"""0.52 quotas: published fair-use limits; 507 for storage, 429 for egress; nothing deleted."""

from __future__ import annotations

import json

from opentine import _jsonschema
from opentine.remote._limits import FAIR_USE, LimitExceeded, Limits
from opentine.remote._openapi import build
from tests._auth_helpers import call, local_run, make_app, push

PACK = "application/vnd.opentine.pack"


def _valid(name: str, value) -> list[str]:
    schema = {"$ref": f"#/components/schemas/{name}", "components": build()["components"]}
    return _jsonschema.validate(schema, value)


def test_limits_and_auth_methods_are_public_unsigned_documents(tmp_path):
    app = make_app(tmp_path / "remote")
    status, _, body = call(app, "GET", "/v1/limits", token=None)
    limits = json.loads(body)
    assert status == 200 and limits["defaults"] == FAIR_USE and limits["never_deletes"] is True
    assert limits["status"] == {"storage_bytes": 507, "egress_bytes": 429, "mirror_bytes": 507,
                                "runner_minutes": 429}  # fmt: skip
    assert _valid("Limits", limits) == []
    methods = json.loads(call(app, "GET", "/v1/auth-methods", token=None)[2])
    assert _valid("AuthMethods", methods) == []


def test_a_full_tenant_gets_507_and_keeps_everything(tmp_path):
    app = make_app(tmp_path / "remote", limits={"tenants": {"acme": {"storage_bytes": 4096}}})
    kept = push(app, tmp_path, "kept", "heads/main")  # in-process: not metered
    run_id, pack = local_run(tmp_path, "small", 500)
    first = call(app, "POST", "/v1/tenants/acme/packs", raw=pack, content_type=PACK)
    assert first[0] == 201
    used = app.limits.used("acme", "storage_bytes")
    assert used == len(pack)
    big_id, big = local_run(tmp_path, "huge", 8000)
    status, headers, body = call(app, "POST", "/v1/tenants/acme/packs", raw=big,
                                 content_type=PACK)  # fmt: skip
    assert (status, json.loads(body)) == (507, {"error": "storage quota exceeded"})
    assert not app.service.objects.has("acme", big_id)
    assert app.service.objects.has("acme", kept) and app.service.objects.has("acme", run_id)
    assert app.service.index.list_refs("acme") == {"heads/main": kept}
    assert app.limits.used("acme", "storage_bytes") == used  # a refusal is not charged
    usage = json.loads(call(app, "GET", "/v1/tenants/acme/usage")[2])
    assert usage["usage"]["storage_bytes"] == {"limit": 4096, "used": used, "window": "total"}
    assert _valid("Usage", usage) == []
    # Another tenant's caller learns nothing about acme's quota: the usual refusal.
    other = call(app, "POST", "/v1/tenants/acme/packs", raw=big, content_type=PACK,
                 token="other-token")  # fmt: skip
    assert other[0] == 403


def test_egress_over_the_daily_limit_is_429_with_retry_after(tmp_path):
    clock = [1_700_000_000.0]
    app = make_app(tmp_path / "remote", limits={"defaults": {"egress_bytes": 2000}})
    app.limits.now = lambda: clock[0]
    push(app, tmp_path, "one", "heads/main")
    seen = []
    for _ in range(50):
        status, headers, _ = call(app, "GET", "/v1/tenants/acme/refs")
        seen.append(status)
        if status == 429:
            break
    assert seen[0] == 200 and seen[-1] == 429
    assert 0 < int(headers["Retry-After"]) <= 86400
    assert call(app, "GET", "/v1/tenants/acme/refs", token=None)[0] == 401  # never an oracle
    assert call(app, "GET", "/v1/limits", token=None)[0] == 200  # public docs are not metered
    clock[0] += 86400
    assert call(app, "GET", "/v1/tenants/acme/refs")[0] == 200  # a new UTC day


def test_null_is_unlimited_and_bad_limit_files_are_refused(tmp_path):
    limits = Limits(tmp_path, {"defaults": {"storage_bytes": None}})
    limits.charge("acme", "storage_bytes", 10**15)
    limits.check("acme", "storage_bytes", 10**15)
    limits.check("acme", "runner_minutes", 5)
    limits.charge("acme", "runner_minutes", FAIR_USE["runner_minutes"])
    try:
        limits.check("acme", "runner_minutes", 1)
    except LimitExceeded as exc:
        assert exc.status == 429 and exc.retry_after
    else:  # pragma: no cover
        raise AssertionError("runner minutes over the limit must refuse")
    for bad in ({"defaults": {"disk": 1}}, {"defaults": {"storage_bytes": -1}},
                {"defaults": {"storage_bytes": True}}, {"other": {}}, {"tenants": []}):  # fmt: skip
        try:
            Limits(tmp_path / "x", bad)
        except ValueError:
            continue
        raise AssertionError(bad)  # pragma: no cover
