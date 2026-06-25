"""Filesystem adapter: simulate a file-mutating action against a shadow copy.

The action is a callable ``action(root: str) -> None`` that mutates files under
``root``. We copy the real sandbox directory to a tempdir, run the action there,
snapshot before/after, and diff. The real directory is never touched. If the
action raises, the effect is fail-closed (recorded in ``unknown``).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from ..delta import AuthorityGrant, CanonicalDelta, DataAccess


@dataclass
class _FileState:
    size: int
    mode: str
    digest: str  # content hash; "" for directories
    is_dir: bool = False


@dataclass
class _FsEffect:
    before: Dict[str, _FileState]
    after: Dict[str, _FileState]
    error: Optional[str] = None


def _digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _snapshot(root: str) -> Dict[str, _FileState]:
    states: Dict[str, _FileState] = {}
    for dirpath, dirs, files in os.walk(root):
        for name in dirs:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            st = os.stat(full)
            states[rel] = _FileState(size=0, mode=oct(st.st_mode & 0o777), digest="", is_dir=True)
        for name in files:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            st = os.stat(full)
            states[rel] = _FileState(size=st.st_size, mode=oct(st.st_mode & 0o777), digest=_digest(full))
    return states


class FilesystemAdapter:
    domain = "filesystem"

    def __init__(self, sandbox: str):
        self.sandbox = sandbox

    def simulate(self, action: Callable[[str], None]) -> _FsEffect:
        tmp = tempfile.mkdtemp(prefix="simdiff-fs-")
        shadow = os.path.join(tmp, "root")
        try:
            shutil.copytree(self.sandbox, shadow)
            before = _snapshot(shadow)
            error = None
            try:
                action(shadow)
            except Exception as exc:  # noqa: BLE001 - fail-closed on any error
                error = f"{type(exc).__name__}: {exc}"
            after = _snapshot(shadow)
            return _FsEffect(before=before, after=after, error=error)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def extract_delta(self, effect: _FsEffect, principal: Optional[str] = None) -> CanonicalDelta:
        if effect.error is not None:
            return CanonicalDelta(unknown=[f"action failed during simulation: {effect.error}"])

        delta = CanonicalDelta()
        before, after = effect.before, effect.after

        for rel, st in after.items():
            if rel not in before:
                reason = "directory created" if st.is_dir else "file created"
                delta.data_access.append(
                    DataAccess(resource=rel, mode="CREATE", bytes=st.size, reason=reason)
                )
            else:
                old = before[rel]
                if not st.is_dir and st.digest != old.digest:
                    delta.data_access.append(
                        DataAccess(
                            resource=rel,
                            mode="WRITE",
                            bytes=st.size - old.size,
                            reason="file contents changed",
                        )
                    )
                if st.mode != old.mode:
                    delta.authority_grants.append(
                        AuthorityGrant(
                            target=rel,
                            kind="mode",
                            old=old.mode,
                            new=st.mode,
                            reason="permission bits changed",
                        )
                    )

        for rel, old in before.items():
            if rel not in after:
                reason = "directory deleted" if old.is_dir else "file deleted"
                delta.data_access.append(
                    DataAccess(resource=rel, mode="DELETE", bytes=0, reason=reason)
                )

        return delta
