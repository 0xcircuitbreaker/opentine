"""Schemas for the query, experiment, elicitation, sabotage, history-merge, budget,
containment, weight custody, model-organism, uplift, trends and transcript-analysis areas.

Collected by :mod:`opentine._schemas`.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs_budget import COMMAND_SCHEMAS as _BUDGET_COMMANDS
from opentine._schema_defs_budget import SCHEMAS as _BUDGET
from opentine._schema_defs_containment import COMMAND_SCHEMAS as _CONTAINMENT_COMMANDS
from opentine._schema_defs_containment import SCHEMAS as _CONTAINMENT
from opentine._schema_defs_custody import COMMAND_SCHEMAS as _CUSTODY_COMMANDS
from opentine._schema_defs_custody import SCHEMAS as _CUSTODY
from opentine._schema_defs_elicit import COMMAND_SCHEMAS as _ELICIT_COMMANDS
from opentine._schema_defs_elicit import SCHEMAS as _ELICIT
from opentine._schema_defs_experiment import COMMAND_SCHEMAS as _EXPERIMENT_COMMANDS
from opentine._schema_defs_experiment import SCHEMAS as _EXPERIMENT
from opentine._schema_defs_keyless import COMMAND_SCHEMAS as _KEYLESS_COMMANDS
from opentine._schema_defs_keyless import SCHEMAS as _KEYLESS
from opentine._schema_defs_merge_history import COMMAND_SCHEMAS as _MH_COMMANDS
from opentine._schema_defs_merge_history import SCHEMAS as _MH
from opentine._schema_defs_organism import COMMAND_SCHEMAS as _ORGANISM_COMMANDS
from opentine._schema_defs_organism import SCHEMAS as _ORGANISM
from opentine._schema_defs_query import COMMAND_SCHEMAS as _QUERY_COMMANDS
from opentine._schema_defs_query import SCHEMAS as _QUERY
from opentine._schema_defs_sabotage import COMMAND_SCHEMAS as _SABOTAGE_COMMANDS
from opentine._schema_defs_sabotage import SCHEMAS as _SABOTAGE
from opentine._schema_defs_transcripts import COMMAND_SCHEMAS as _TRANSCRIPTS_COMMANDS
from opentine._schema_defs_transcripts import SCHEMAS as _TRANSCRIPTS
from opentine._schema_defs_trends import COMMAND_SCHEMAS as _TRENDS_COMMANDS
from opentine._schema_defs_trends import SCHEMAS as _TRENDS
from opentine._schema_defs_uplift import COMMAND_SCHEMAS as _UPLIFT_COMMANDS
from opentine._schema_defs_uplift import SCHEMAS as _UPLIFT

SCHEMAS: dict[str, dict[str, Any]] = {
    **_QUERY,
    **_EXPERIMENT,
    **_ELICIT,
    **_SABOTAGE,
    **_MH,
    **_BUDGET,
    **_CONTAINMENT,
    **_CUSTODY,
    **_ORGANISM,
    **_UPLIFT,
    **_TRENDS,
    **_TRANSCRIPTS,
    **_KEYLESS,
}
COMMAND_SCHEMAS: dict[str, str] = {
    **_QUERY_COMMANDS,
    **_EXPERIMENT_COMMANDS,
    **_ELICIT_COMMANDS,
    **_SABOTAGE_COMMANDS,
    **_MH_COMMANDS,
    **_BUDGET_COMMANDS,
    **_CONTAINMENT_COMMANDS,
    **_CUSTODY_COMMANDS,
    **_ORGANISM_COMMANDS,
    **_UPLIFT_COMMANDS,
    **_TRENDS_COMMANDS,
    **_TRANSCRIPTS_COMMANDS,
    **_KEYLESS_COMMANDS,
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
