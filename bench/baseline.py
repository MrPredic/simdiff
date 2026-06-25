"""Baseline: signature / keyword scanning of the raw action string.

This is a faithful stand-in for the common practice of denylisting dangerous
patterns in a tool call's arguments. It is intentionally a *reasonable* denylist
(case-insensitive, covers the obvious destructive forms) — not a strawman. Its
weakness is structural: it reads the request, not the effect, so any obfuscation
that preserves the effect while changing the surface text gets through.
"""

from __future__ import annotations

import re

_DENYLIST = [
    r"\brm\s+-[rf]+\b",        # rm -rf / rm -fr
    r"\bdrop\s+table\b",       # DROP TABLE
    r"\bdelete\s+from\b",      # DELETE FROM
    r"\btruncate\b",
    r"\bchmod\s+0?777\b",      # world-writable via numeric mode
    r"\bmkfs\b",
    r">\s*/dev/sd",            # overwrite a block device
    r":\(\)\s*\{",             # fork bomb
]
_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _DENYLIST]


def keyword_flag(action: str) -> bool:
    """True if the raw action string matches any dangerous signature."""
    return any(p.search(action) for p in _PATTERNS)
