"""Schemas for the query, experiment, elicitation, sabotage, history-merge, budget,
containment, weight custody, model-organism, interpretability, uplift, trends,
transcript-analysis, ingest, scorer-isolation, eval-plan and tripwire areas.

Collected by :mod:`opentine._schemas`.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs_bom import COMMAND_SCHEMAS as _BOM_COMMANDS
from opentine._schema_defs_bom import SCHEMAS as _BOM
from opentine._schema_defs_budget import COMMAND_SCHEMAS as _BUDGET_COMMANDS
from opentine._schema_defs_budget import SCHEMAS as _BUDGET
from opentine._schema_defs_containment import COMMAND_SCHEMAS as _CONTAINMENT_COMMANDS
from opentine._schema_defs_containment import SCHEMAS as _CONTAINMENT
from opentine._schema_defs_curate import COMMAND_SCHEMAS as _CURATE_COMMANDS
from opentine._schema_defs_curate import SCHEMAS as _CURATE
from opentine._schema_defs_custody import COMMAND_SCHEMAS as _CUSTODY_COMMANDS
from opentine._schema_defs_custody import SCHEMAS as _CUSTODY
from opentine._schema_defs_dataset_contrib import COMMAND_SCHEMAS as _CONTRIB_COMMANDS
from opentine._schema_defs_dataset_contrib import SCHEMAS as _CONTRIB
from opentine._schema_defs_elicit import COMMAND_SCHEMAS as _ELICIT_COMMANDS
from opentine._schema_defs_elicit import SCHEMAS as _ELICIT
from opentine._schema_defs_experiment import COMMAND_SCHEMAS as _EXPERIMENT_COMMANDS
from opentine._schema_defs_experiment import SCHEMAS as _EXPERIMENT
from opentine._schema_defs_ingest import COMMAND_SCHEMAS as _INGEST_COMMANDS
from opentine._schema_defs_ingest import SCHEMAS as _INGEST
from opentine._schema_defs_interp import COMMAND_SCHEMAS as _INTERP_COMMANDS
from opentine._schema_defs_interp import SCHEMAS as _INTERP
from opentine._schema_defs_judge import COMMAND_SCHEMAS as _JUDGE_COMMANDS
from opentine._schema_defs_judge import SCHEMAS as _JUDGE
from opentine._schema_defs_keyless import COMMAND_SCHEMAS as _KEYLESS_COMMANDS
from opentine._schema_defs_keyless import SCHEMAS as _KEYLESS
from opentine._schema_defs_merge_history import COMMAND_SCHEMAS as _MH_COMMANDS
from opentine._schema_defs_merge_history import SCHEMAS as _MH
from opentine._schema_defs_organism import COMMAND_SCHEMAS as _ORGANISM_COMMANDS
from opentine._schema_defs_organism import SCHEMAS as _ORGANISM
from opentine._schema_defs_plan import COMMAND_SCHEMAS as _PLAN_COMMANDS
from opentine._schema_defs_plan import SCHEMAS as _PLAN
from opentine._schema_defs_policy import COMMAND_SCHEMAS as _POLICY_COMMANDS
from opentine._schema_defs_policy import SCHEMAS as _POLICY
from opentine._schema_defs_provenance import COMMAND_SCHEMAS as _PROVENANCE_COMMANDS
from opentine._schema_defs_provenance import SCHEMAS as _PROVENANCE
from opentine._schema_defs_query import COMMAND_SCHEMAS as _QUERY_COMMANDS
from opentine._schema_defs_query import SCHEMAS as _QUERY
from opentine._schema_defs_sabotage import COMMAND_SCHEMAS as _SABOTAGE_COMMANDS
from opentine._schema_defs_sabotage import SCHEMAS as _SABOTAGE
from opentine._schema_defs_scorer import COMMAND_SCHEMAS as _SCORER_COMMANDS
from opentine._schema_defs_scorer import SCHEMAS as _SCORER
from opentine._schema_defs_transcripts import COMMAND_SCHEMAS as _TRANSCRIPTS_COMMANDS
from opentine._schema_defs_transcripts import SCHEMAS as _TRANSCRIPTS
from opentine._schema_defs_trends import COMMAND_SCHEMAS as _TRENDS_COMMANDS
from opentine._schema_defs_trends import SCHEMAS as _TRENDS
from opentine._schema_defs_tripwire import COMMAND_SCHEMAS as _TRIPWIRE_COMMANDS
from opentine._schema_defs_tripwire import SCHEMAS as _TRIPWIRE
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
    **_INTERP,
    **_PROVENANCE,
    **_UPLIFT,
    **_TRENDS,
    **_TRANSCRIPTS,
    **_CURATE,
    **_BOM,
    **_CONTRIB,
    **_POLICY,
    **_KEYLESS,
    **_INGEST,
    **_SCORER,
    **_PLAN,
    **_JUDGE,
    **_TRIPWIRE,
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
    **_INTERP_COMMANDS,
    **_PROVENANCE_COMMANDS,
    **_UPLIFT_COMMANDS,
    **_TRENDS_COMMANDS,
    **_TRANSCRIPTS_COMMANDS,
    **_CURATE_COMMANDS,
    **_BOM_COMMANDS,
    **_CONTRIB_COMMANDS,
    **_POLICY_COMMANDS,
    **_KEYLESS_COMMANDS,
    **_INGEST_COMMANDS,
    **_SCORER_COMMANDS,
    **_PLAN_COMMANDS,
    **_JUDGE_COMMANDS,
    **_TRIPWIRE_COMMANDS,
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
