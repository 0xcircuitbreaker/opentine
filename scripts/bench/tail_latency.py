"""Live-tail latency bench (0.77): how long after an event is durable does a follower show it?

Two paths, both measured from the moment the writer's ref move returned (the
event is durable) to the moment the follower yields its row:

* ``--mode cli``: the ``tine log -f`` engine (:class:`opentine._tail.Follower`)
  polling a local repository every ``--interval`` seconds while a writer thread
  appends events in write batches of ``--batch`` (the ref moves after each
  batch is durable), a new run every ``--run-events``, followed with ``--all``;
* ``--mode sse``: ``GET /v1/tenants/acme/tail?all=1`` on an in-process
  reference ``tine serve`` app, the stream read frame by frame, while the
  writer installs packs and moves refs through the service (so the ref move
  wakes the stream).

Target (plan 0.77): tail latency under 1 s. Results and hardware are recorded
in docs/bench/0.77-tail.md. Example::

    python scripts/bench/tail_latency.py --mode cli --seconds 60 --rate 2000
"""

from __future__ import annotations

import argparse
import io
import json
import platform
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from opentine._tail import Follower  # noqa: E402
from opentine.repository import Repo  # noqa: E402
from opentine.repository._write_batch import batched  # noqa: E402


class Writer(threading.Thread):
    def __init__(self, args, put, stop: threading.Event):
        super().__init__(daemon=True)
        self.args, self.put, self.stop = args, put, stop
        self.durable: dict[str, float] = {}
        self.lock = threading.Lock()
        self.written = 0

    def run(self) -> None:
        args, start = self.args, time.perf_counter()
        run, number = None, 0
        while not self.stop.is_set():
            if run is None or len(run) >= args.run_events:
                number += 1
                run = []
            events = self.put(run, args.batch, f"experiments/bench/{number:06d}")
            self.written += args.batch
            done = time.perf_counter()
            with self.lock:
                for oid in events[-args.batch :]:
                    self.durable[oid] = done
            ahead = self.written / args.rate - (done - start)
            if ahead > 0:
                self.stop.wait(ahead)


def append(repo: Repo, events: list[str], count: int) -> str:
    """*count* events appended to *events* in one write batch; the new run object's oid."""
    with batched(repo):
        for _ in range(count):
            parents = events[-1:]
            payload = {"kind": "model", "parent_ids": parents, "causal_ids": [],
                       "time_unix": time.time(), "cost": 0, "duration": 0}  # fmt: skip
            events.append(repo.put("event", payload))
        run = {"events": events, "roots": events[:1], "tips": events[-1:], "status": "running",
               "model": "", "created_at": 0, "manifests": {}}  # fmt: skip
        return repo.put("run", run)


def _cli(args, tmp: Path):
    repo = Repo.init(tmp / "repo")

    def put(events, count, ref):
        oid = append(repo, events, count)
        repo.update_ref(ref, oid, repo.read_ref(ref))  # after the batch is durable
        return events

    follower = Follower(repo, repo.list_refs, backlog=0)

    def rows():
        while True:
            found = follower.poll(5000)
            yield from found
            if not found:
                time.sleep(args.interval)

    return put, rows()


def _sse(args, tmp: Path):
    from opentine._cli_watch import parse_sse
    from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server

    ids = StaticTokenIdentityProvider({"t": Identity("bench", "acme", ("writer",))})
    app = server.reference_app(tmp / "remote", identities=ids, keys=LocalKeyProvider(b"k" * 32))
    app.stream_seconds = args.seconds + 60
    service = app.service
    who = service.authenticate({"authorization": "Bearer t"})
    local = Repo.init(tmp / "local")
    sent: set[str] = set()

    def put(events, count, ref):
        known = len(events)
        oid = append(local, events, count)
        new = [e for e in events[known:] if e not in sent] + [oid]
        service.install_pack(who, "acme", local.pack(new))
        sent.update(new)
        old = service.index.list_refs("acme").get(ref)
        service.update_ref(who, "acme", ref, oid, old)
        return events

    environ = {"PATH_INFO": "/v1/tenants/acme/tail", "QUERY_STRING": "all=1",
               "REQUEST_METHOD": "GET", "HTTP_AUTHORIZATION": "Bearer t",
               "CONTENT_LENGTH": "0", "wsgi.input": io.BytesIO(b"")}  # fmt: skip
    body = app(environ, lambda status, headers: None)

    def lines():
        pending = b""
        for chunk in body:
            pending += chunk
            *done, pending = pending.split(b"\n")
            yield from (line.decode() for line in done)

    def rows():
        for frame in parse_sse(lines()):
            if frame.get("event") == "event":
                yield json.loads(frame["data"])

    return put, rows()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=("cli", "sse"), default="cli")
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--rate", type=float, default=1000.0, help="target events per second")
    parser.add_argument("--batch", type=int, default=50, help="events per ref move")
    parser.add_argument("--run-events", type=int, default=500, help="events per run")
    parser.add_argument("--interval", type=float, default=0.05, help="cli poll interval")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="tine-tail-bench-") as tmp:
        put, rows = (_cli if args.mode == "cli" else _sse)(args, Path(tmp))
        stop = threading.Event()
        writer = Writer(args, put, stop)
        latencies: list[float] = []
        writer.start()
        deadline = time.perf_counter() + args.seconds
        for item in rows:
            seen = time.perf_counter()
            with writer.lock:
                durable = writer.durable.pop(item["event_id"], None)
            if durable is not None:
                latencies.append(max(0.0, seen - durable))
            if seen >= deadline:
                break
        stop.set()
        writer.join()
    latencies.sort()

    def pct(p: float) -> float:
        return round(latencies[min(len(latencies) - 1, int(p * len(latencies)))], 4)

    result = {
        "mode": args.mode, "seconds": args.seconds, "target_rate": args.rate,
        "achieved_rate": round(writer.written / args.seconds, 1), "events_seen": len(latencies),
        "batch": args.batch, "interval": args.interval,
        "p50": pct(0.50), "p95": pct(0.95), "p99": pct(0.99), "max": round(latencies[-1], 4),
        "under_1s": all(v < 1.0 for v in latencies),
        "machine": {"python": platform.python_version(), "cpu": platform.processor()
                    or platform.machine(), "system": platform.platform()},
    }  # fmt: skip
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
