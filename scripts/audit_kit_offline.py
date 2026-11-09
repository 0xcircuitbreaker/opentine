"""Build an audit kit, then verify it air-gapped: the 0.49 CI job (1.0 criterion 4).

    python scripts/audit_kit_offline.py build DIR    # needs no network either
    python scripts/audit_kit_offline.py verify DIR   # run with networking disabled

``build`` records and signs a fresh run, pins two witness keys and writes the
kit with a ``replay/v1`` attestation. ``verify`` runs ``tine audit-kit verify
DIR --pyz`` (every in-process check inside the offline guard, and the kit's
own ``tine-verify.pyz`` in a separate process, which refuses the network
itself), then the stdlib-only ``ae/verify_kit.py`` under ``python -I``. CI runs
``verify`` on Linux, macOS and Windows; on Linux also inside ``unshare --net``,
where no network interface but loopback exists.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def build(out: Path) -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import Run, RunStatus, StepKind, cli
    from opentine.repository._tlog_cosign import witness_vkey
    from opentine.signing import generate_ed25519

    room = Path(tempfile.mkdtemp(prefix="tine-kit-ci-"))
    private, public = generate_ed25519()
    (room / "k").write_text(private, encoding="ascii")
    (room / "k").chmod(0o600)
    (room / "k.pub").write_text(public + "\n", encoding="ascii")
    run = Run(user_prompt="audit kit CI", model_info="model-a")
    run.add_step(StepKind.model, {"messages": [{"role": "user", "content": "hi"}]}, {"t": "ok"})
    run.status = RunStatus.completed
    run.save(room / "run.tine")
    sign = ["sign", str(room / "run.tine"), "--algorithm", "ed25519", "--ed25519-key-file",
            str(room / "k"), "--save", str(room / "run.tine"), "--overwrite"]  # fmt: skip
    cli.main(sign)
    vkeys = [
        witness_vkey(name, Ed25519PrivateKey.generate().public_key().public_bytes_raw())
        for name in ("witness-a", "witness-b")
    ]
    argv = ["audit-kit", "build", str(room / "run.tine"), "--out", str(out), "--zip",
            "--pubkey", str(room / "k.pub"), "--attest-key", str(room / "k"),
            "--witness", vkeys[0], "--witness", vkeys[1], "--quorum", "2-of-2",
            "--operator", "ci"]  # fmt: skip
    # The trust anchor travels apart from the kit, as an auditor's would.
    _anchor(out).write_text(public + "\n", encoding="ascii")
    try:
        cli.main(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    finally:
        shutil.rmtree(room, ignore_errors=True)  # the private key goes with it
    return 0


def _anchor(kit: Path) -> Path:
    return kit.with_name(kit.name + "-signer.pub")


def verify(kit: Path) -> int:
    from opentine import cli

    for target in (kit, kit.with_name(kit.name + ".zip")):
        if not target.exists():
            continue
        try:
            cli.main(["audit-kit", "verify", str(target), "--pyz", "--pubkey", str(_anchor(kit))])
        except SystemExit as exc:
            if exc.code:
                return int(exc.code)
    ae = [sys.executable, "-I", str(kit / "ae" / "verify_kit.py"), str(_anchor(kit))]
    done = subprocess.run(ae, check=False)
    return done.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("action", choices=("build", "verify"))
    parser.add_argument("kit", help="kit directory")
    args = parser.parse_args(argv)
    kit = Path(args.kit)
    return build(kit) if args.action == "build" else verify(kit)


if __name__ == "__main__":
    sys.exit(main())
