"""Windows process containment: a child is in its kill-on-close job before it runs.

``run_bounded`` used to start the child running and attach the Job Object
afterwards; a grandchild spawned in that window was born outside the job and
survived the kill (``test_windows_job_cleans_descendant_after_normal_parent_exit``
caught it on a loaded CI runner). The child now starts suspended. These tests pin
the ordering with fake kernel32/ntdll objects, so they run on every platform; the
real Windows behaviour is exercised by the round-5 Job Object tests.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from opentine.tools._winjob import contain_suspended


class _Kernel:
    def __init__(self, calls: list[str], *, assign_ok: bool = True):
        self.calls = calls
        self.assign_ok = assign_ok

    def CreateJobObjectW(self, *_):
        self.calls.append("create-job")
        return 7

    def SetInformationJobObject(self, *_):
        return 1

    def AssignProcessToJobObject(self, *_):
        self.calls.append("assign")
        return 1 if self.assign_ok else 0

    def CloseHandle(self, *_):
        self.calls.append("close-job")
        return 1

    def TerminateProcess(self, *_):
        self.calls.append("terminate")
        return 1


class _Ntdll:
    def __init__(self, calls: list[str], status: int = 0):
        self.calls = calls
        self.status = status

    def NtResumeProcess(self, *_):
        self.calls.append("resume")
        return self.status


def _process(calls: list[str]):
    return SimpleNamespace(_handle=42, kill=lambda: calls.append("kill"))


def test_the_child_joins_the_job_before_it_is_resumed():
    calls: list[str] = []
    job = contain_suspended(_process(calls), kernel=_Kernel(calls), ntdll=_Ntdll(calls))
    assert job is not None
    assert calls == ["create-job", "assign", "resume"]


def test_a_child_is_resumed_even_when_no_job_can_hold_it(monkeypatch):
    # Job attachment is best effort (the caller keeps its taskkill fallback), but
    # a child left suspended would hang the caller until its timeout.
    monkeypatch.setattr("ctypes.get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr("ctypes.WinError", lambda code=None: OSError(code), raising=False)
    calls: list[str] = []
    job = contain_suspended(
        _process(calls), kernel=_Kernel(calls, assign_ok=False), ntdll=_Ntdll(calls)
    )
    assert job is None
    assert calls == ["create-job", "assign", "close-job", "resume"]


def test_a_child_that_cannot_be_resumed_is_terminated_never_left_suspended():
    calls: list[str] = []
    with pytest.raises(OSError, match="NTSTATUS 0xc0000022"):
        contain_suspended(
            _process(calls), kernel=_Kernel(calls), ntdll=_Ntdll(calls, status=-1073741790)
        )
    assert calls == ["create-job", "assign", "resume", "terminate", "close-job"]


def test_a_missing_windows_api_kills_the_child_rather_than_stranding_it(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        "opentine.tools._winjob._kernel32", lambda: (_ for _ in ()).throw(OSError("no kernel32"))
    )
    with pytest.raises(OSError, match="no kernel32"):
        contain_suspended(_process(calls))
    assert calls == ["kill"]
