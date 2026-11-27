"""The isolated scorer child (0.85): run as ``python -I _scorer_child.py`` by the parent.

Stdlib only, and nothing from :mod:`opentine` is imported before the scorer, so
the child holds no signing key and no repository handle. It reads one JSON
request file (its first argument, removed once read): ``nonce``, ``target``,
``paths``, ``inputs``, ``limits`` and ``pairs``. Then, before the scorer is imported:

* lowers its own CPU, address-space, file-size and open-file limits, soft and
  hard (POSIX; a lowered hard limit cannot be raised again);
* on Linux, moves into a fresh user and network namespace, so it has no
  network interface to reach (``network: namespace``); elsewhere, or when the
  kernel refuses, sockets are refused by the audit hook only (``network: audit``);
* empties ``os.environ`` and watches it: a read from non-stdlib code is a breach;
* installs an audit hook that refuses sockets, subprocesses, ``ctypes``, any
  file write and any file read outside the interpreter, the scorer's import
  paths and the inputs the parent passed explicitly.

It prints one line, ``nonce`` + JSON: ``scores``, ``breaches``, ``modules``
(non-stdlib modules the call imported) and ``data`` (other files it read).
"""

import json
import os
import sys
import sysconfig

_STD = [sysconfig.get_paths()[k] for k in ("stdlib", "platstdlib")]
_SITE = [sysconfig.get_paths()[k] for k in ("purelib", "platlib")]
_BLOCK = ("socket.", "subprocess.", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
          "os.fork", "os.forkpty", "ctypes.", "os.putenv", "os.unsetenv", "os.remove",
          "os.rename", "os.rmdir", "os.mkdir", "os.chmod", "os.truncate", "shutil.",
          "os.kill", "signal.", "sys.addaudithook", "sys.settrace", "sys.setprofile", "gc.",
          "pty.", "winreg.")  # fmt: skip
_DEVICES = ("/dev/null", "/dev/urandom")


def _norm(path):
    return os.path.normcase(os.path.realpath(path))


def _under(path, roots):
    return any(path == r or path.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


def _stdlib(path):
    real = _norm(path)
    return _under(real, [_norm(p) for p in _STD]) and not _under(real, [_norm(p) for p in _SITE])


def _scorer_on_stack(frame):
    """True when non-stdlib code (the scorer) asked, outside an import of stdlib code."""
    here = _norm(__file__)
    while frame is not None:
        name = frame.f_code.co_filename
        if name.startswith("<frozen importlib"):
            return False
        if not name.startswith("<") and not _stdlib(name):
            return _norm(name) != here
        frame = frame.f_back
    return False


def _limits(limits):
    try:
        import resource
    except ImportError:
        return False
    table = {"RLIMIT_CPU": limits["cpu_seconds"], "RLIMIT_AS": limits["memory_mb"] << 20,
             "RLIMIT_FSIZE": 0, "RLIMIT_NOFILE": 256, "RLIMIT_CORE": 0}  # fmt: skip
    done = True
    for name, value in table.items():
        try:
            resource.setrlimit(getattr(resource, name), (value, value))
        except (AttributeError, ValueError, OSError):
            done = name not in ("RLIMIT_CPU", "RLIMIT_AS") and done
    return done


def _unshare():
    if not sys.platform.startswith("linux"):
        return False
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        return libc.unshare(0x10000000 | 0x40000000) == 0  # CLONE_NEWUSER | CLONE_NEWNET
    except (OSError, AttributeError):
        return False


class _Env(dict):
    def __init__(self, record):
        super().__init__()
        self._record = record

    def _seen(self):
        if _scorer_on_stack(sys._getframe(2)):
            self._record("env", "os.environ was read")

    def __getitem__(self, key):
        self._seen()
        raise KeyError(key)

    def get(self, key, default=None):
        self._seen()
        return default

    def __contains__(self, key):
        self._seen()
        return False

    def __iter__(self):
        self._seen()
        return iter(())

    def keys(self):
        self._seen()
        return []

    def items(self):
        self._seen()
        return []

    def copy(self):
        self._seen()
        return {}


def main():
    sys.dont_write_bytecode = True
    with open(sys.argv[1], "rb") as handle:
        request = json.loads(handle.read().decode("utf-8"))
    os.remove(sys.argv[1])  # the nonce is gone before the scorer runs
    breaches, data = [], set()
    contained = _limits(request["limits"])
    network = "namespace" if _unshare() else "audit"
    # Bytecode is read only from an empty prefix, so a planted .pyc never runs.
    sys.pycache_prefix = os.path.join(os.getcwd(), "pycache")
    allowed = [_norm(p) for p in [*_STD, *_SITE, *request["paths"], *request["inputs"]]]
    allowed.append(_norm(sys.pycache_prefix))

    def record(kind, detail):
        breaches.append({"kind": kind, "detail": detail[:200]})

    def hook(event, args):
        if event.startswith(_BLOCK):
            record("network" if event.startswith("socket.") else "process", event)
            raise PermissionError(f"isolated scorer: {event} is refused")
        if event not in ("open", "os.listdir", "os.scandir") or not args:
            return
        path = args[0]
        if not isinstance(path, str | bytes) or (isinstance(path, str) and path in _DEVICES):
            return
        path = os.fsdecode(path)
        mode = args[1] if event == "open" and len(args) > 1 and isinstance(args[1], str) else "r"
        flags = args[2] if event == "open" and len(args) > 2 and isinstance(args[2], int) else 0
        if any(c in mode for c in "wax+") or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
            record("file-write", path)
            raise PermissionError(f"isolated scorer: writing {path} is refused")
        real = _norm(path)
        if not _under(real, allowed):
            record("file-read", path)
            raise PermissionError(f"isolated scorer: reading {path} is refused")
        if (
            event == "open"
            and not _stdlib(real)
            and os.path.isfile(real)
            and not _under(real, [_norm(sys.pycache_prefix)])
        ):
            data.add(os.path.realpath(path))

    sys.stdout.flush()
    out = os.fdopen(os.dup(1), "w", encoding="utf-8")
    sys.stdout = sys.stderr
    os.environ.clear()
    os.environ = _Env(record)
    before = set(sys.modules)
    sys.addaudithook(hook)
    sys.path[:0] = request["paths"]
    scores, error = [], None
    try:
        func = _load(request["target"])
        for item, output in request["pairs"]:
            scores.append(_coerce(func(output, item)))
    except BaseException as exc:  # noqa: BLE001 - report it; the parent decides
        error = f"{type(exc).__name__}: {exc}"[:500]
    modules = {}
    for name, module in list(sys.modules.items()):
        where = getattr(module, "__file__", None)
        if name in before or not isinstance(where, str) or _stdlib(where):
            continue
        modules[name] = os.path.realpath(where)
    result = {"scores": scores, "error": error, "breaches": breaches, "modules": modules,
              "data": sorted(data - set(modules.values())), "network": network,
              "limits": contained}  # fmt: skip
    out.write(request["nonce"] + json.dumps(result, sort_keys=True) + "\n")
    out.flush()


def _load(target):
    import importlib
    import importlib.util

    location, _, name = target.rpartition(":")
    if location.endswith(".py"):
        spec = importlib.util.spec_from_file_location(
            os.path.splitext(os.path.basename(location))[0], location)  # fmt: skip
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    else:
        module = importlib.import_module(location)
    return getattr(module, name)


def _coerce(value):
    if isinstance(value, dict):
        value = value.get("score")
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, int | float) and 0 <= value <= 1:
        return float(value)
    raise ValueError(f"a scorer returned {value!r}, not a bool or a number in 0..1")


if __name__ == "__main__":
    main()
