"""Run many branches of one run at once: ``tine fan-out`` and ``tine run --parallel``.

* :mod:`._matrix` -- ``--vary``/``--repeat`` expansion, argv templating, member env;
* :mod:`._executor` -- the bounded concurrent executor (process-tree kills, timeouts,
  the shared :class:`opentine.budget.SharedLedger`);
* :mod:`._state` -- the resumable on-disk fan-out state;
* :mod:`._status` -- human and NDJSON status lines;
* :mod:`._fanout` -- forks from one fork point (one walk), refs and the record.
"""

from opentine.parallel._executor import Executor, Member, Outcome
from opentine.parallel._matrix import expand, parse_vary, render

__all__ = ["Executor", "Member", "Outcome", "expand", "parse_vary", "render"]
