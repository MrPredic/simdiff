"""A frozen snapshot of `ShellAdapter` as it existed before the 2026-07
read-only/pipeline vocabulary expansion (commit before that change).

This exists **only** for `bench/realistic_shell_run.py` to report an honest
before/after number for the real-command-stream false-positive rate the
README used to warn about. It is not part of the public API, not exported,
and not exercised by the main test suite — do not import it outside `bench/`.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Iterable, List, Optional, Set, Tuple

from simdiff.delta import AuthorityGrant, CanonicalDelta, DataAccess

_PRODUCERS = {"echo", "printf", "cat", "true", ":", "head", "tail"}
_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;|\n)\s*")
_UNMODELLED = re.compile(r"[|&$`<*?~{}\[\]]|[^\s>]>|>[^\s>]")


def _norm(path: str) -> str:
    return os.path.normpath(path)


class LegacyShellAdapter:
    domain = "shell"

    def __init__(self, existing: Optional[Iterable[str]] = None):
        self.existing: Set[str] = {_norm(p) for p in (existing or ())}

    def simulate(self, action: str) -> List[str]:
        return [seg for seg in _SPLIT_RE.split((action or "").strip()) if seg.strip()]

    def extract_delta(self, effect: List[str], principal: Optional[str] = None) -> CanonicalDelta:
        delta = CanonicalDelta()
        for segment in effect:
            if _UNMODELLED.search(segment):
                delta.unknown.append(f"unmodelled shell construct, cannot certify: {segment!r}")
                continue
            try:
                tokens = shlex.split(segment)
            except ValueError as exc:
                delta.unknown.append(f"unparseable command ({exc}): {segment!r}")
                continue
            self._apply(tokens, delta)
        return delta

    def _apply(self, tokens: List[str], delta: CanonicalDelta) -> None:
        if not tokens:
            return
        tokens, redirects = self._strip_redirects(tokens)
        for target, append in redirects:
            t = _norm(target)
            mode = "WRITE" if (append or t in self.existing) else "CREATE"
            delta.data_access.append(DataAccess(resource=t, mode=mode, reason="shell redirect"))
        if not tokens:
            return

        verb = tokens[0]
        if verb in ("cp", "mv") and any(
            a.startswith("-") and not a.startswith("--") and "t" in a[1:] for a in tokens[1:]
        ):
            delta.unknown.append(f"unmodelled flag (-t takes a value, inverts operands): {verb}")
            return

        args = [_norm(a) for a in tokens[1:] if not a.startswith("-")]
        handler = getattr(self, f"_cmd_{verb}", None)
        if handler is not None:
            handler(args, delta)
        elif verb in _PRODUCERS:
            return
        else:
            delta.unknown.append(f"unknown command, cannot certify: {verb}")

    @staticmethod
    def _strip_redirects(tokens: List[str]) -> Tuple[List[str], List[Tuple[str, bool]]]:
        out: List[str] = []
        redirects: List[Tuple[str, bool]] = []
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t in (">", ">>") and i + 1 < len(tokens):
                redirects.append((tokens[i + 1], t == ">>"))
                i += 2
                continue
            out.append(t)
            i += 1
        return out, redirects

    def _cmd_rm(self, args, delta):
        for a in args:
            if a in self.existing:
                delta.data_access.append(DataAccess(resource=a, mode="DELETE", reason="rm"))

    _cmd_rmdir = _cmd_rm

    def _cmd_mkdir(self, args, delta):
        for a in args:
            delta.data_access.append(DataAccess(resource=a, mode="CREATE", reason="mkdir"))

    def _cmd_touch(self, args, delta):
        for a in args:
            mode = "WRITE" if a in self.existing else "CREATE"
            delta.data_access.append(DataAccess(resource=a, mode=mode, reason="touch"))

    def _cmd_mv(self, args, delta):
        if len(args) < 2:
            delta.unknown.append("mv: could not parse source/destination")
            return
        *srcs, dst = args
        for src in srcs:
            if src in self.existing:
                delta.data_access.append(DataAccess(resource=src, mode="DELETE", reason="mv source"))
        mode = "WRITE" if dst in self.existing else "CREATE"
        delta.data_access.append(DataAccess(resource=dst, mode=mode, reason="mv destination"))

    def _cmd_cp(self, args, delta):
        if len(args) < 2:
            delta.unknown.append("cp: could not parse source/destination")
            return
        *srcs, dst = args
        for src in srcs:
            delta.data_access.append(DataAccess(resource=src, mode="READ", reason="cp source"))
        mode = "WRITE" if dst in self.existing else "CREATE"
        delta.data_access.append(DataAccess(resource=dst, mode=mode, reason="cp destination"))

    def _cmd_chmod(self, args, delta):
        if len(args) < 2:
            delta.unknown.append("chmod: could not parse mode/target")
            return
        new_mode, targets = args[0], args[1:]
        for t in targets:
            delta.authority_grants.append(
                AuthorityGrant(target=t, kind="mode", old="?", new=new_mode, reason="chmod")
            )
