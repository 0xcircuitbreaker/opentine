"""The supervisor program :mod:`opentine.tools._subreaper` starts (Linux).

It runs ``python -I -S -c SUPERVISOR REPORT_FD SECRET_FD TOKEN ARGV...``. The
report pipe carries ``pid <shim>`` and, after a sweep, ``ok`` -- each line
prefixed with a nonce read from SECRET_FD, a pipe OpenTine wrote before the
start and the supervisor closes at once. The command runs as the same user and
can open OpenTine's end of the report pipe through ``/proc``, so an unprefixed
``ok`` proved nothing (re-audit round 2, #7): it cannot read the nonce, which
lives only in this process, made non-dumpable before reading it, so its
``/proc/<pid>/{fd,mem,environ}`` are closed to the command.
"""

SUPERVISOR = r"""
import ctypes, os, signal, sys
fd, secret, token, argv = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4:]
os.set_inheritable(fd, False)
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE 0: our fds and memory closed to the command
nonce = b""
while len(nonce) < 256:
    chunk = os.read(secret, 256)
    if not chunk:
        break
    nonce += chunk
os.close(secret)
nonce = nonce.decode().strip()
def report(text):
    try:
        os.write(fd, f"{nonce} {text}".encode())
    except OSError:
        pass
if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    report("unsupported\n")
    os.close(fd)
    os.execvp(argv[0], argv)
os.environ["OPENTINE_TOOL_SCOPE"] = token
def children(pid):
    found = []
    try:
        tasks = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return found
    for task in tasks:
        try:
            with open(f"/proc/{pid}/task/{task}/children") as handle:
                found.extend(int(item) for item in handle.read().split())
        except (OSError, ValueError):
            pass
    return found
def sweep():
    me = os.getpid()
    for _ in range(1000):
        stack, seen = children(me), []
        while stack:
            pid = stack.pop()
            seen.append(pid)
            stack.extend(children(pid))
        if not seen:
            return
        for pid in seen:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        while True:
            try:
                if os.waitpid(-1, os.WNOHANG)[0] == 0:
                    break
            except ChildProcessError:
                break
def mirror(status):
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        try:
            signal.signal(sig, signal.SIG_DFL)
        except (OSError, ValueError):
            pass  # SIGKILL/SIGSTOP cannot be caught, so they need no reset
        os.kill(os.getpid(), sig)
    os._exit(os.waitstatus_to_exitcode(status) & 0xFF)
def stop(*_):
    sweep()
    report("ok\n")
    os._exit(137)
signal.signal(signal.SIGTERM, stop)
shim = os.fork()
if shim == 0:
    try:
        os.close(fd)
        os.setpgid(0, 0)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        pid = os.fork()
        if pid == 0:
            try:
                os.execvp(argv[0], argv)
            except OSError as exc:
                os.write(2, f"[Errno {exc.errno}] {exc.strerror}: {argv[0]!r}\n".encode())
            os._exit(127)
        while True:
            try:
                status = os.waitpid(pid, 0)[1]
                break
            except InterruptedError:
                continue
        mirror(status)
    finally:
        os._exit(127)
report(f"pid {shim}\n")
while True:
    try:
        status = os.waitpid(shim, 0)[1]
        break
    except InterruptedError:
        continue
sweep()
report("ok\n")
mirror(status)
"""

__all__ = ["SUPERVISOR"]
