"""Public SDK for one-file harness importers; see :mod:`opentine.harnesses._adapter_spec`.

Ship an adapter as an ``opentine.adapters`` entry point naming an
:class:`AdapterSpec` (or a function returning one). Users enable it by name in
``$XDG_CONFIG_HOME/opentine/adapters.json``; nothing else loads it.
"""

from opentine.harnesses._adapter_spec import AdapterSpec, check, run_adapter

__all__ = ["AdapterSpec", "check", "run_adapter"]
