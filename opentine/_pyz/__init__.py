"""The sources of ``tine-verify.pyz``: an offline verifier with no native code.

Every module here imports the standard library and, relatively, two modules the
build vendors verbatim beside it: :mod:`opentine.kernel` (canonical JSON, the
envelope and oid rules, link validation) and :mod:`opentine._ed25519_order`
(the small-order key refusal). Nothing else from opentine is imported, so the
same files run inside the package (``python -m opentine._pyz``) and inside the
zipapp ``scripts/build_verifier.py`` writes, where they sit in ``tine_verify/``.

The verdicts are the ``tine verify --offline`` ones for the checks this
verifier runs (``digest``, ``signature``) and the evidence folder checks of
``docs/conformance/minimal_verifier.py``. zstd-coded content is refused with
a message naming ``tine evidence export --with-verifier``, which re-exports it
in the stdlib-readable archival form.
"""
