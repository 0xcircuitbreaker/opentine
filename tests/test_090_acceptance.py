"""0.90 acceptance, end to end: monitors as evidence, and role tokens on ``tine serve``."""

from __future__ import annotations

import json

import pytest

from opentine import (
    _ingest_holds,
    _monitor_coverage,
    _monitor_heartbeat,
    _monitor_ledger,
    _monitor_suspicion,
    _monitor_validation,
    _monitor_verdict,
    _oversight_queue,
)
from opentine._monitor_runner import Runner
from opentine._monitor_verdict import monitors
from tests._auth_helpers import make_app, push
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import T0, config, event, ingest, key, repo_fixture  # noqa: F401
from tests.test_090_monitor_operating_point import _labelled
from tests.test_090_role_tokens import _decide, _key, _put_ref, _review_of, _routes, _upload
from tests.test_090_role_tokens import role_token as _role

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
MIN = 60_000


def _codes(body: dict, level: str) -> set[str]:
    return {f["code"] for f in body["findings"] if f["level"] == level}


def test_monitors_as_evidence_end_to_end(repo):
    cfg = config()
    ident = _monitor_ledger.identity(cfg)
    now = {"ms": T0 + 1_000}
    runner = Runner(repo, cfg, "rl", key("monitor"), clock_ms=lambda: now["ms"])
    ingest(repo, [event("ls"), event("rm -rf /")] + [event(f"probe {n}", session=f"s{n}")
                                                     for n in range(3)], T0)  # fmt: skip
    assert runner.counts.get("evaluated", 0) == 0
    runner.once()
    runner.heartbeat()
    # category and severity reach the signed verdict
    claims = [repo.get(o).payload()["claim"] for o in _monitor_verdict.held(repo)]
    assert {(c.get("category"), c.get("severity")) for c in claims} >= {("destructive", "high")}

    def report(**kw):
        return _monitor_coverage.report(repo, "rl", ident, threshold=0.5,
                                        now_ms=kw.pop("now_ms", T0 + 2_000), **kw)  # fmt: skip

    assert report()["covered"] == "5/5"
    # an unseen batch is reported as a gap of exactly its events
    ingest(repo, [event("ls 2")], T0 + 5)
    gap = report()
    assert gap["covered"] == "5/6" and gap["gaps"] == [[5, 5]]
    assert "advisory:monitor.coverage-gap" in _codes(gap, "advisory")
    assert not _codes(gap, "fail")  # advisory never blocks by default
    # under rsi, coverage needs a validated operating point, and fails closed without one
    rsi = report(profile="rsi")
    assert rsi["counts_as_coverage"] is False and rsi["evaluated"] == 0 and _codes(rsi, "fail")
    point = _monitor_validation.evaluate(cfg, _labelled())
    _monitor_validation.record(repo, ident, point, key("scorer"), "2027-01-15T08:00:00Z")
    now["ms"] = T0 + 30_000
    runner.once()
    runner.heartbeat()
    good = report(profile="rsi", now_ms=T0 + 31_000)
    assert good["covered"] == "6/6" and good["counts_as_coverage"] and not _codes(good, "fail")
    # a monitor that stops beating goes stale
    batches, _ = _monitor_ledger.walk(repo, _ingest_holds.head(repo, "rl"),
                                      "opentine.ingest-batch/1")  # fmt: skip
    hb = _monitor_heartbeat.check(repo, ident, "rl", batches, now_ms=now["ms"] + 10 * MIN,
                                  keys=monitors(repo)[0], gating=True)  # fmt: skip
    assert hb["stale_windows"] and "fail:monitor.stale" in {f["code"] for f in hb["findings"]}
    # cumulative suspicion across sessions is a doom-loop flag routed to oversight
    scan = _monitor_suspicion.scan(repo, _monitor_ledger.chains(repo), monitors(repo)[0])
    assert any(f["subject"] == "agent:a1" for f in scan["flags"])
    assert _monitor_suspicion.items(repo)
    assert "suspicion" in {row["source"] for row in _oversight_queue._sources(repo)}


def test_role_tokens_end_to_end(tmp_path):
    app = make_app(tmp_path / "remote")
    ingest_tok, _ = _role(app, "ingest", ["heads/agent-7/"], agent="agent-7")
    verdict_tok, _ = _role(app, "verdict", ["heads/monitors/"], agent="mon-1")
    approver, _ = _role(app, "approve", ["*"], agent="agent-7")
    own, status = _upload(app, tmp_path, "own", ingest_tok)
    assert status == 201 and _put_ref(app, "heads/agent-7/x", own, ingest_tok) == 200
    for method, path, body in _routes(own):  # ingest-only reads nothing
        assert _status(app, method, path, body, ingest_tok) in (403, 404)
    verdict, status = _upload(app, tmp_path, "v", verdict_tok)
    assert status == 201 and _put_ref(app, "heads/monitors/v", verdict, verdict_tok) == 200
    other = push(app, tmp_path, "other", "heads/main")
    k, pub = _key()
    theirs, mine = _review_of(app, other, k, pub, "theirs"), _review_of(app, own, k, pub, "mine")
    assert _decide(app, theirs, k, verdict_tok)[0] in (403, 404)  # verdict-only cannot approve
    assert _decide(app, theirs, k, ingest_tok)[0] in (403, 404)
    assert _decide(app, theirs, k, approver)[0] == 201  # approve-only decides
    refused = _decide(app, mine, k, approver)
    assert refused[0] == 403 and json.loads(refused[2])["code"] == "token.self-approval"
    assert _upload(app, tmp_path, "sneak", approver)[1] in (403, 404)


def _status(app, method, path, body, token) -> int:
    from tests._auth_helpers import call

    return call(app, method, path, body, token)[0]
