"""Path components a file system would resolve to ``.git``.

The fs tool refuses writes inside ``.git``. Comparing ``part.lower() ==
".git"`` missed spellings that some file systems map onto the same entry:
Windows drops trailing dots and spaces (``.git.``, ``.git ``), resolves 8.3
short names (``GIT~1``) and alternate data streams (``.git::$INDEX_ALLOCATION``);
HFS+ ignores certain zero-width code points inside a name. git defends its
own checkouts against these with ``core.protectNTFS``/``protectHFS``; this is
the same rule for the fs tool, applied on every platform so a repository
moved between machines is never planted.
"""

from __future__ import annotations

import re

#: Code points HFS+ ignores when comparing names (git's ``is_hfs_dotgit``).
_HFS_IGNORABLE = dict.fromkeys(
    [0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0xFEFF]
    + list(range(0x206A, 0x2070))
)
_SHORT_NAME = re.compile(r"(?i)^git~\d+$")


def is_dotgit(part: str) -> bool:
    """Whether path component *part* names (or aliases) a ``.git`` entry."""
    name = part.translate(_HFS_IGNORABLE)
    name = name.split(":", 1)[0]  # an NTFS stream names its file
    name = name.rstrip(". ").casefold()
    return name == ".git" or bool(_SHORT_NAME.match(name))
