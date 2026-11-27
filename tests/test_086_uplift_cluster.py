"""0.86: the hierarchical (cluster) bootstrap in ``tine uplift``.

Attempts within a task share a task effect, so they are not independent: the
cluster bootstrap (tasks, then attempts inside each drawn task) must give a
wider interval than the flat one, and a recorded seed must reproduce it.
"""

from __future__ import annotations

import math
import random
from fractions import Fraction

import pytest

from opentine import _schemas
from opentine._uplift_report import report_horizon

SUITE = "sha256:" + "5a" * 32


def _export(seed: int = 3, tasks: int = 12, attempts: int = 30) -> dict:
    rng = random.Random(seed)
    table = [{"id": f"t{i:02d}", "minutes": str(2**i)} for i in range(tasks)]
    records = []
    for task in table:
        shift = rng.choice((-1.5, 1.5))  # a strong per-task effect shared by its attempts
        z = -0.8 * (math.log2(int(task["minutes"])) - math.log2(60)) + shift
        p = 1.0 / (1.0 + math.exp(-z))
        for n in range(attempts):
            records.append({"oid": f"sha256:{len(records):064x}", "record": "run",
                            "task": task["id"], "subject": f"s{n % 3}", "condition": "ai",
                            "success": rng.random() < p, "minutes": None,
                            "perceived_minutes": None, "generation": None})  # fmt: skip
    return {"format": "opentine-uplift-export/1", "suite": SUITE,
            "definition": {"name": "s", "version": "1", "scoring": "binary", "tasks": table},
            "records": records, "findings": []}  # fmt: skip


def _width(body: dict) -> Fraction:
    lo, hi = body["fit"]["ci"]
    return Fraction(hi) / Fraction(lo)


def test_clustered_data_gives_a_wider_interval_than_the_naive_bootstrap() -> None:
    export = _export()
    naive = report_horizon(export, seed=7, resamples=300)
    cluster = report_horizon(export, seed=7, resamples=300, bootstrap="cluster")
    assert naive["bootstrap"] == "naive" and naive["cluster_key"] is None
    assert cluster["bootstrap"] == "cluster" and cluster["cluster_key"] == "task"
    assert naive["fit"]["horizon_minutes"] == cluster["fit"]["horizon_minutes"]
    assert _width(cluster) > _width(naive)
    for body in (naive, cluster):
        _schemas.validate({"command": "uplift horizon", "schema": "tine-cli-uplift/1", **body},
                          "tine-cli-uplift-1")  # fmt: skip


def test_recorded_seed_resamples_and_method_reproduce_the_interval() -> None:
    export = _export()
    args = {"seed": 11, "resamples": 200, "bootstrap": "cluster", "cluster_key": "subject"}
    first = report_horizon(export, **args)
    again = report_horizon(export, **{k: first[k] for k in args})
    assert first == again and first["cluster_key"] == "subject"
    other = report_horizon(export, **{**args, "seed": 12})
    assert other["fit"]["ci"] != first["fit"]["ci"]


def test_an_unknown_method_or_cluster_key_is_refused() -> None:
    with pytest.raises(ValueError, match="--bootstrap"):
        report_horizon(_export(), resamples=100, bootstrap="block")
    with pytest.raises(ValueError, match="--cluster-key"):
        report_horizon(_export(), resamples=100, bootstrap="cluster", cluster_key="family")
