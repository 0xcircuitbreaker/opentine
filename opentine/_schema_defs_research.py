"""Schemas for the query, experiment, elicitation and sabotage areas (:mod:`opentine._schemas`)."""

from __future__ import annotations

from typing import Any

from opentine._schema_defs_elicit import COMMAND_SCHEMAS as _ELICIT_COMMANDS
from opentine._schema_defs_elicit import SCHEMAS as _ELICIT
from opentine._schema_defs_experiment import COMMAND_SCHEMAS as _EXPERIMENT_COMMANDS
from opentine._schema_defs_experiment import SCHEMAS as _EXPERIMENT
from opentine._schema_defs_query import COMMAND_SCHEMAS as _QUERY_COMMANDS
from opentine._schema_defs_query import SCHEMAS as _QUERY
from opentine._schema_defs_sabotage import COMMAND_SCHEMAS as _SABOTAGE_COMMANDS
from opentine._schema_defs_sabotage import SCHEMAS as _SABOTAGE

SCHEMAS: dict[str, dict[str, Any]] = {**_QUERY, **_EXPERIMENT, **_ELICIT, **_SABOTAGE}
COMMAND_SCHEMAS: dict[str, str] = {
    **_QUERY_COMMANDS,
    **_EXPERIMENT_COMMANDS,
    **_ELICIT_COMMANDS,
    **_SABOTAGE_COMMANDS,
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
