"""Drop test ids that look like credentials from the pytest-split durations file.

Some redaction tests are parametrised with fake tokens, and those ids would put
credential-shaped strings in a committed file. An id is dropped if OpenTine's own
redactor would change it, or if it matches the extra patterns below. pytest-split
gives a test missing from the file the average duration, so dropping them only
shifts the shard balance slightly.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from opentine.redaction import redact_blob

CREDENTIAL_SHAPED = re.compile(
    r"xox[a-z]-|gh[pousr]_|github_pat_|gl[a-z]{2}-|AKIA|ASIA|sk-|-----BEGIN|eyJ[A-Za-z0-9_-]{8}"
)


def credential_shaped(test_id: str) -> bool:
    return (
        bool(CREDENTIAL_SHAPED.search(test_id)) or redact_blob(test_id.encode()) != test_id.encode()
    )


def scrub(durations: dict[str, float]) -> dict[str, float]:
    return {k: v for k, v in sorted(durations.items()) if not credential_shaped(k)}


def main(argv: list[str]) -> int:
    path = Path(argv[1] if len(argv) > 1 else "tests/test_durations.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    kept = scrub(data)
    path.write_text(json.dumps(kept, indent=2) + "\n", encoding="utf-8")
    print(f"scrub_durations: kept {len(kept)} of {len(data)} test ids")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
