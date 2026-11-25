"""0.83 review: holes a loop or a colluding monitor could use, each closed.

1. The gate (and ``tine interp score``) runs a probe monitor only while it matches
   its calibration: a probe or threshold swapped after calibration, or a
   calibration signed by an optimizer key, fails closed instead of scoring.
2. Custody cannot be laundered: a second, untagged record of a tagged artifact's
   bytes, or a re-encoded copy keyed to the same checkpoint, is still under
   custody.
"""

from __future__ import annotations

import json

import pytest

from opentine import _interp_custody as ic
from opentine import _probe_monitor as pm
from opentine._monitor_gate import Gate
from opentine._monitors import load
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_083_probe_monitor import (
    CKPT,
    WIDTH,
    _config,
    _key,
    _probe,
    _samples,
    _tine,
    room,  # noqa: F401
)

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

CALM = {"opentine/activations": {"checkpoint_digest": CKPT, "activations": [0.0] * WIDTH}}


def _decide(room, **over):  # noqa: F811
    gate = Gate(load(_config(room, **over)), repo=room["repo"], key=_key("monitor"))
    return gate.decide("tools/call", {"name": "ls", "arguments": {}, "_meta": CALM})


def test_the_gate_scores_a_probe_that_matches_its_calibration(room):  # noqa: F811
    assert _decide(room)["outcome"] == "forward"


def test_the_gate_blocks_when_the_threshold_was_changed_after_calibration(room):  # noqa: F811
    got = _decide(room, threshold=0.999)
    assert (got["outcome"], got["claim"]["decided_by"]) == ("block", "error")


def test_the_gate_blocks_a_probe_swapped_after_calibration(room):  # noqa: F811
    swapped = _probe(scale=0.001)
    (room["tmp"] / "probe.json").write_bytes(swapped)
    got = _decide(room, probe=ic.digest(swapped))
    assert (got["outcome"], got["claim"]["decided_by"]) == ("block", "error")


def test_the_gate_blocks_on_an_optimizer_signed_calibration(room):  # noqa: F811
    bad = pm.calibrate(room["repo"], room["probe"], _key("optimizer"), threshold=0.5,
                       samples=_samples(2))  # fmt: skip
    got = _decide(room, calibration=bad["record"])
    assert (got["outcome"], got["claim"]["decided_by"]) == ("block", "error")


def test_score_refuses_a_probe_that_no_longer_matches_its_calibration(room, capsys):  # noqa: F811
    request = room["tmp"] / "req.json"
    request.write_bytes(json.dumps(CALM["opentine/activations"]).encode("utf-8"))
    code, body = _tine(capsys, "interp", "score", _config(room, threshold=0.999), "--request",
                       request.as_posix(), "--repo", room["where"], "--json")  # fmt: skip
    assert code != 0 and "probe.threshold-changed" in json.dumps(body)


GRAPH = b'{"nodes": ["f1"]}'


def test_an_untagged_second_record_does_not_launder_a_tagged_artifact(room):  # noqa: F811
    repo = room["repo"]
    ic.store(repo, GRAPH, kind="attribution-graph", checkpoint=CKPT, key=_key("runner"),
             tags=["model-organism"])  # fmt: skip
    for signer in ("optimizer", "runner"):
        ic.store(repo, GRAPH, kind="attribution-graph", checkpoint=CKPT, key=_key(signer))
        with pytest.raises(ic.CustodyDenied):
            ic.export(repo, ic.digest(GRAPH), run="r-1")


def test_a_re_encoded_copy_on_the_same_checkpoint_stays_under_custody(room):  # noqa: F811
    repo = room["repo"]
    ic.store(repo, GRAPH, kind="attribution-graph", checkpoint=CKPT, key=_key("runner"),
             tags=["model-organism"])  # fmt: skip
    copy = json.dumps(json.loads(GRAPH), indent=2).encode("utf-8")
    ic.store(repo, copy, kind="attribution-graph", checkpoint=CKPT, key=_key("optimizer"))
    with pytest.raises(ic.CustodyDenied):
        ic.export(repo, ic.digest(copy), run="r-1")
