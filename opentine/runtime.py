"""Public runtime facade composed from focused implementation modules."""

from opentine._runtime_accounting import AccountingMixin
from opentine._runtime_agent import AgentBase
from opentine._runtime_history import HistoryMixin, _messages_from_transcript
from opentine._runtime_loop import RuntimeLoopMixin
from opentine._runtime_model import Model


class Agent(RuntimeLoopMixin, AccountingMixin, HistoryMixin, AgentBase):
    """Execute provider-neutral model/tool runs with provenance and billing."""


__all__ = ["Agent", "Model", "_messages_from_transcript"]
