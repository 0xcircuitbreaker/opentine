"""R6: monitor ids bound to their signer keys, bad thresholds, normalized doom-loop keys."""

from __future__ import annotations

import pytest

from opentine import (
    _ingest_holds,
    _monitor_coverage,
    _monitor_ledger,
    _monitor_suspicion,
    _trust_bundle,
)
from opentine._ingest_policy import anchor
from opentine._monitor_runner import Runner
from opentine._monitor_verdict import monitors
from opentine.repository._holds import MONITOR_LEDGER
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.monitor_ledger_helpers import (  # noqa: F401
    CONFIG,
    T0,
    config,
    event,
    fpr,
    ingest,
    key,
    pin_monitors,
    repo_fixture,
)

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
RENAMED = CONFIG.replace('id = "rules"', 'id = "rules2"')


def _codes(body: dict, level: str = "fail") -> set[str]:
    return {f["code"] for f in body["findings"] if f["level"] == level}


def _cover(repo, text=CONFIG, name="monitor", **kw):
    cfg = config(text)
    Runner(repo, cfg, "rl", key(name), clock_ms=lambda: T0 + 1_000).once()
    return _monitor_coverage.report(repo, "rl", _monitor_ledger.identity(cfg),
                                    now_ms=T0 + 2_000, threshold=0.5, **kw)  # fmt: skip


def _scan(repo, name="monitor"):
    Runner(repo, config(), "rl", key(name), clock_ms=lambda: T0 + 1_000).once()
    return _monitor_suspicion.scan(repo, _monitor_ledger.chains(repo), monitors(repo)[0])


def test_another_pinned_monitor_key_cannot_sign_for_a_bound_monitor(repo):
    ingest(repo, [event(f"ls {i}") for i in range(3)], T0)
    body = _cover(repo, name="monitor2")  # a pinned monitor key, but bound to no monitor
    assert "fail:monitor.coverage-unsigned" in _codes(body)
    assert body["evaluated"] == 0 and body["covered"] == "0/3"
    assert any("not bound to rules" in f["message"] for f in body["findings"])


def test_heartbeats_from_another_monitors_key_are_no_liveness(repo):
    ingest(repo, [event("ls")], T0)
    Runner(repo, config(), "rl", key("monitor2"), clock_ms=lambda: T0 + 500).heartbeat()
    body = _cover(repo)
    assert body["heartbeats"]["last_ms"] is None
    assert "fail:monitor.heartbeat-unsigned" in _codes(body)


def test_a_renamed_monitor_id_is_unbound_and_fails_closed_under_rsi(repo):
    ingest(repo, [event(f"ls {i}") for i in range(3)], T0)
    loose = _cover(repo, RENAMED)
    assert "advisory:monitor.signer-unbound" in _codes(loose, "advisory")
    assert loose["evaluated"] == 3  # D12: advisory by default
    rsi = _monitor_coverage.report(repo, "rl", _monitor_ledger.identity(config(RENAMED)),
                                   now_ms=T0 + 2_000, threshold=0.5, profile="rsi")  # fmt: skip
    assert "fail:monitor.signer-unbound" in _codes(rsi) and rsi["evaluated"] == 0


def test_one_key_bound_to_two_monitors_is_refused(repo):
    with pytest.raises(_trust_bundle.BundleError, match="monitors"):
        pin_monitors(repo, {"rules": [fpr("monitor")], "rules2": [fpr("monitor")]})
    with pytest.raises(_trust_bundle.BundleError, match="monitors"):
        pin_monitors(repo, {"rules": [fpr("monitor")]}, required=["unbound"])


def test_suspicion_ignores_a_ledger_signed_by_another_monitors_key(repo):
    for n in range(3):
        ingest(repo, [event(f"probe {n}")], T0 + n)
    assert _scan(repo, "monitor2")["flags"] == []


def _forge_threshold(repo, threshold):
    head = _monitor_ledger.head(repo, "rules", "rl")
    claim = dict(_monitor_ledger.read(repo, head)["claim"])
    claim.update(seq=claim["seq"] + 1, previous=head, threshold=threshold)
    oid = _ingest_holds.write(repo, anchor(repo, "rl"), claim, key("monitor"), previous=head,
                              signed_at=claim["at"], verbatim=("events",))  # fmt: skip
    _ingest_holds.move_head(repo, "rules@rl", head, oid, prefix=MONITOR_LEDGER)
    return oid


@pytest.mark.parametrize("threshold", ["high", "NaN", "inf", True, None])
def test_a_record_with_a_bad_threshold_is_reported_never_a_crash(repo, threshold):
    for n in range(3):
        ingest(repo, [event(f"probe {n}")], T0 + n)
    Runner(repo, config(), "rl", key("monitor"), clock_ms=lambda: T0 + 1_000).once()
    oid = _forge_threshold(repo, threshold)
    body = _monitor_suspicion.scan(repo, _monitor_ledger.chains(repo), monitors(repo)[0])
    assert [r["record"] for r in body["invalid"]] == [oid]
    report = _monitor_coverage.report(repo, "rl", _monitor_ledger.identity(config()),
                                      now_ms=T0 + 2_000, threshold=0.5)  # fmt: skip
    assert any(f["code"] == "fail:monitor.coverage-forged" and f["record"] == oid
               for f in report["findings"])  # fmt: skip


def test_changing_one_argument_per_retry_is_still_a_repeated_failure(repo):
    for n in range(3):  # a fresh identity and a fresh path each time: no exact digest repeats
        ingest(repo, [event(f"rm -rf /srv/{n}", agent=f"x{n}", session=f"y{n}", run=f"z{n}")],
               T0 + n)  # fmt: skip
    flags = {(f["code"], f["subject"].split(":")[0]) for f in _scan(repo)["flags"]}
    assert ("advisory:monitor.doom-loop-repeated-failure", "shape") in flags
    assert ("advisory:monitor.doom-loop-repeated-failure", "action") not in flags


def test_varied_benign_usage_is_not_a_repeated_failure(repo):
    commands = ["sudo rm -rf /a", "find / -exec rm -rf {}", "xargs rm -rf"]
    ingest(repo, [event(c, agent=f"x{n}", session=f"y{n}", run=f"z{n}")
                  for n, c in enumerate(commands)], T0)  # fmt: skip
    ingest(repo, [event(f"ls /srv/{n}") for n in range(40)], T0 + 1)  # one shape, all allowed
    flags = {f["code"] for f in _scan(repo)["flags"]}
    assert "advisory:monitor.doom-loop-repeated-failure" not in flags
