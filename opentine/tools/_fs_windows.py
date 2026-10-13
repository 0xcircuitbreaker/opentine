"""Windows: list a sandboxed directory through a handle, never by name.

POSIX lists a directory through a descriptor reached from the root one component
at a time (``_fs_open``). Windows has no ``dir_fd``, and any user can create a
junction, so a directory listed by path after the check could be a junction
swapped in meanwhile. Here the directory is opened once, the handle's final path
must be the path that was checked, and the entries are read from that handle
(``GetFileInformationByHandleEx``): nothing swapped in later changes the listing.
"""

from __future__ import annotations

import ctypes
import os
import struct
from pathlib import Path

_LIST_DIRECTORY = 0x0001
_SHARE_ALL = 0x1 | 0x2 | 0x4
_OPEN_EXISTING = 3
_BACKUP_SEMANTICS = 0x02000000  # required to open a directory
_FULL_DIRECTORY_INFO = 14  # FILE_INFO_BY_HANDLE_CLASS.FileFullDirectoryInfo
_FULL_DIRECTORY_RESTART = 15
_NO_MORE_FILES = 18
_ATTRIBUTE_DIRECTORY = 0x10
#: FILE_FULL_DIR_INFO: NextEntryOffset @0, FileAttributes @56,
#: FileNameLength (bytes) @60, FileName (UTF-16LE) @68.
_NAME_OFFSET = 68
_BUFFER_BYTES = 64 * 1024


def parse_entries(raw: bytes) -> list[tuple[bool, str]]:
    """Entries of one FILE_FULL_DIR_INFO buffer, as ``(is_dir, name)``."""
    entries: list[tuple[bool, str]] = []
    offset = 0
    while offset + _NAME_OFFSET <= len(raw):
        (step,) = struct.unpack_from("<I", raw, offset)
        attributes, size = struct.unpack_from("<II", raw, offset + 56)
        start = offset + _NAME_OFFSET
        if start + size > len(raw):
            raise OSError("malformed directory information from the file system")
        name = raw[start : start + size].decode("utf-16-le")
        if name not in (".", ".."):
            entries.append((bool(attributes & _ATTRIBUTE_DIRECTORY), name))
        if not step:
            break
        offset += step
    return entries


def list_directory(resolved: Path, limit: int) -> list[tuple[bool, str]]:
    """Up to ``limit + 1`` entries of the directory at ``resolved``, read via its handle."""
    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(
        str(resolved), _LIST_DIRECTORY, _SHARE_ALL, None, _OPEN_EXISTING, _BACKUP_SEMANTICS, None
    )
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
    try:
        if os.path.normcase(_final_path(kernel32, handle)) != os.path.normcase(str(resolved)):
            raise PermissionError(f"Path changed while it was opened: {resolved}")
        entries: list[tuple[bool, str]] = []
        buffer = ctypes.create_string_buffer(_BUFFER_BYTES)
        kind = _FULL_DIRECTORY_RESTART
        while len(entries) <= limit:
            if not kernel32.GetFileInformationByHandleEx(handle, kind, buffer, _BUFFER_BYTES):
                error = ctypes.get_last_error()  # type: ignore[attr-defined]
                if error == _NO_MORE_FILES:
                    break
                raise ctypes.WinError(error)  # type: ignore[attr-defined]
            kind = _FULL_DIRECTORY_INFO
            entries.extend(parse_entries(buffer.raw))
        return entries[: limit + 1]
    finally:
        kernel32.CloseHandle(handle)


def _final_path(kernel32, handle) -> str:
    size = 512
    while True:
        buffer = ctypes.create_unicode_buffer(size)
        length = kernel32.GetFinalPathNameByHandleW(handle, buffer, size, 0)
        if not length:
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
        if length < size:
            break
        size = length + 1
    path = buffer.value
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    return path.removeprefix("\\\\?\\")


def _kernel32():
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return kernel32
