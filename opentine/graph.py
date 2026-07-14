"""Public compatibility graph facade; implementations stay in small modules."""

from opentine._canon import FORMAT_VERSION, SUPPORTED_VERSIONS
from opentine._graph_analysis import RunAnalysisMixin
from opentine._graph_diff import _position_keys
from opentine._graph_persistence import RunPersistenceMixin
from opentine._graph_run import RunBase
from opentine._graph_serde import (
    graph_from_dict as _graph_from_dict,
)
from opentine._graph_serde import (
    run_from_dict as _run_from_dict_impl,
)
from opentine._graph_serde import (
    step_from_dict as _step_from_dict,
)
from opentine._graph_serde import (
    step_to_dict as _step_to_dict,
)
from opentine._graph_types import (
    FieldDelta,
    Graph,
    IntegrityResult,
    RunDiff,
    RunStatus,
    Step,
    StepChange,
    StepKind,
    _normalize_tag,
    _normalize_tags,
    short_id,
    step_id,
)


class Run(RunAnalysisMixin, RunPersistenceMixin, RunBase):
    """Backward-compatible mutable view over v2 files and v3 repositories."""


def _run_from_dict(data):
    return _run_from_dict_impl(data, Run)


__all__ = [
    "FORMAT_VERSION",
    "SUPPORTED_VERSIONS",
    "FieldDelta",
    "Graph",
    "IntegrityResult",
    "Run",
    "RunDiff",
    "RunStatus",
    "Step",
    "StepChange",
    "StepKind",
    "short_id",
    "step_id",
    "_graph_from_dict",
    "_normalize_tag",
    "_normalize_tags",
    "_position_keys",
    "_run_from_dict",
    "_step_from_dict",
    "_step_to_dict",
]
