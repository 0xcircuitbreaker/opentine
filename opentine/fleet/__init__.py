"""Fleets: many agent processes declared in one trusted ``fleet.toml``.

* :mod:`._manifest` -- parsing, validation and exact-bytes trust;
* :mod:`._runner` -- launching members on :class:`opentine.parallel.Executor`,
  the on-disk state, stop requests and cost.

``tine fleet up/status/stop/cost`` is the CLI (:mod:`opentine._cli_fleet`).
"""

from opentine.fleet._manifest import Agent, Fleet, load, parse
from opentine.fleet._runner import cost, create, run

__all__ = ["Agent", "Fleet", "cost", "create", "load", "parse", "run"]
