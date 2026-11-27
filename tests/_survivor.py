"""A ``setsid()`` descendant that reports its pid, and a bounded check that it died.

The process-cleanup tests spawn a descendant that leaves the process group and
writes a marker file two seconds later. Sleeping past those two seconds and
checking the marker is absent passes on a slow runner even when the descendant
survived, because it may simply not have reached the write yet. Here the
descendant writes its pid before anything else, the spawner waits for that
file, and the test polls ``/proc`` until the pid is gone (or a zombie): a
survivor fails after the generous bound instead of passing silently. Linux only.
"""

from __future__ import annotations

import time
from pathlib import Path


def spawn(tmp_path: Path, marker: str, *, prefix: str = "") -> str:
    """Python lines that start the descendant and return once its pid file exists."""
    pid_file, target = tmp_path / f"{marker}.pid", tmp_path / marker
    child = (
        f"{prefix}import os, time; open(r'{pid_file}.tmp', 'w').write(str(os.getpid())); "
        f"os.replace(r'{pid_file}.tmp', r'{pid_file}'); time.sleep(2); open(r'{target}', 'w')"
    )
    return (
        "import os, subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {child!r}], start_new_session=True)\n"
        "for _ in range(6000):\n"
        f"    if os.path.exists(r'{pid_file}'):\n"
        "        break\n"
        "    time.sleep(0.005)\n"
    )


def gone(tmp_path: Path, marker: str, *, bound: float = 60.0) -> bool:
    """Whether the descendant spawned as *marker* has exited and wrote no marker."""
    pid = int((tmp_path / f"{marker}.pid").read_text())
    deadline = time.monotonic() + bound
    while time.monotonic() < deadline:
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            break
        if stat.rsplit(")", 1)[1].split()[0] in ("Z", "X"):
            break
        time.sleep(0.05)
    else:
        return False
    return not (tmp_path / marker).exists()
