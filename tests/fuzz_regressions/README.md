# Fuzz regressions

Triaged crash inputs from `scripts/fuzz.py`, one directory per target
(`otlp-spans`, `otlp-logs`, `tine`, `pack`, `localpack`, `dsse`, `inspect`), each a
`<sha256[:16]>.bin` exactly as the fuzzer wrote it to `fuzz-crashes/<target>/`.
`tests/test_053_fuzz_harness.py` replays every file (it must read or be refused
with the reader's documented error) and the fuzzer seeds from them. See
"The 72-hour fuzz run" in `docs/RELEASING.md`.
