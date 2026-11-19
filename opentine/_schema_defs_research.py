"""Schemas for the query and experiment areas, gathered for :mod:`opentine._schemas`."""

from __future__ import annotations

from typing import Any

from opentine._schema_defs_experiment import COMMAND_SCHEMAS as _EXPERIMENT_COMMANDS
from opentine._schema_defs_experiment import SCHEMAS as _EXPERIMENT
from opentine._schema_defs_query import COMMAND_SCHEMAS as _QUERY_COMMANDS
from opentine._schema_defs_query import SCHEMAS as _QUERY

SCHEMAS: dict[str, dict[str, Any]] = {**_QUERY, **_EXPERIMENT}
COMMAND_SCHEMAS: dict[str, str] = {**_QUERY_COMMANDS, **_EXPERIMENT_COMMANDS}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
