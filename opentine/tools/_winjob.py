"""Minimal Windows Job Object support for subprocess-tree ownership."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import Any

_KILL_ON_JOB_CLOSE = 0x00002000
_EXTENDED_LIMIT_INFORMATION = 9

#: ``CreateProcess`` flag. A child created running can spawn a grandchild before
#: ``AssignProcessToJobObject`` reaches it, and that grandchild is outside the
#: job: it survives the kill-on-close. Created suspended, the child cannot run a
#: single instruction until it is already in the job.
CREATE_SUSPENDED = 0x00000004


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    )


class _IoCounters(ctypes.Structure):
    _fields_ = (
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    )


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


class KillJob:
    """A job handle whose close terminates every associated process."""

    def __init__(self, kernel: Any, handle: Any):
        self._kernel = kernel
        self._handle = handle

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None and not self._kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass


def _kernel32() -> Any:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel.TerminateProcess.restype = wintypes.BOOL
    return kernel


def _ntdll() -> Any:
    # NtResumeProcess: the process-wide resume psutil's Process.resume() uses.
    # subprocess.Popen closes the primary thread's handle, so ResumeThread is
    # not available to us.
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    ntdll.NtResumeProcess.restype = ctypes.c_long
    return ntdll


def try_attach_kill_job(process: Any, *, kernel: Any = None) -> KillJob | None:
    """Attach ``process`` to a kill-on-close job, or permit the safe fallback."""
    handle = None
    try:
        kernel = kernel if kernel is not None else _kernel32()
        handle = kernel.CreateJobObjectW(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        information = _ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = _KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(
            handle,
            _EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.AssignProcessToJobObject(handle, wintypes.HANDLE(int(process._handle))):
            raise ctypes.WinError(ctypes.get_last_error())
        return KillJob(kernel, handle)
    except (AttributeError, OSError, TypeError, ValueError):
        if kernel is not None and handle:
            kernel.CloseHandle(handle)
        return None


def contain_suspended(process: Any, *, kernel: Any = None, ntdll: Any = None) -> KillJob | None:
    """Put a ``CREATE_SUSPENDED`` process in a kill-on-close job, then let it run.

    The child is resumed whether or not the job could be attached -- a job is a
    best effort (the caller keeps its taskkill fallback), but a child left
    suspended would hang the caller until its timeout. If it cannot be resumed it
    is terminated and the error raised, never left half-started.
    """
    try:
        kernel = kernel if kernel is not None else _kernel32()
        ntdll = ntdll if ntdll is not None else _ntdll()
    except (AttributeError, OSError):
        process.kill()
        raise
    job = try_attach_kill_job(process, kernel=kernel)
    handle = wintypes.HANDLE(int(process._handle))
    status = ntdll.NtResumeProcess(handle)
    if status != 0:
        kernel.TerminateProcess(handle, 1)
        if job is not None:
            job.close()
        code = status & 0xFFFFFFFF
        raise OSError(f"could not resume the contained process (NTSTATUS {code:#010x})")
    return job
