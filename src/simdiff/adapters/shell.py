"""Shell adapter: a *safe interpreter* for common mutating commands.

It never executes anything. It parses a command line and resolves the file
effects of a known set of commands (``rm``, ``rmdir``, ``mv``, ``cp``, ``mkdir``,
``touch``, ``chmod`` and ``>``/``>>`` redirects) against a snapshot of which
paths currently exist. Any command it does not understand is fail-closed
(recorded in ``unknown``), so an attacker cannot smuggle effects past it.
"""

from __future__ import annotations

import re
import shlex
from typing import Iterable, List, Optional, Set, Tuple

from ..delta import AuthorityGrant, CanonicalDelta, DataAccess

# commands that produce no effect on their own (only via a redirect)
_PRODUCERS = {"echo", "printf", "cat", "true", ":", "head", "tail"}
_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;|\n)\s*")


class ShellAdapter:
    domain = "shell"

    def __init__(self, existing: Optional[Iterable[str]] = None):
        self.existing: Set[str] = set(existing or ())

    def simulate(self, action: str) -> List[List[str]]:
        # "simulation" is purely lexical: split into individual commands.
        return [shlex.split(cmd) for cmd in _SPLIT_RE.split(action.strip()) if cmd.strip()]

    def extract_delta(self, effect: List[List[str]], principal: Optional[str] = None) -> CanonicalDelta:
        delta = CanonicalDelta()
        for tokens in effect:
            self._apply(tokens, delta)
        return delta

    # --- internals -------------------------------------------------------

    def _apply(self, tokens: List[str], delta: CanonicalDelta) -> None:
        if not tokens:
            return
        tokens, redirects = self._strip_redirects(tokens)
        for target, append in redirects:
            mode = "WRITE" if (append or target in self.existing) else "CREATE"
            delta.data_access.append(
                DataAccess(resource=target, mode=mode, reason="shell redirect")
            )
        if not tokens:
            return

        verb, args = tokens[0], [a for a in tokens[1:] if not a.startswith("-")]
        handler = getattr(self, f"_cmd_{verb}", None)
        if handler is not None:
            handler(args, delta)
        elif verb in _PRODUCERS:
            return  # effect, if any, was via redirect
        else:
            delta.unknown.append(f"unknown command: {verb}")

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
        src, dst = args[0], args[-1]
        if src in self.existing:
            delta.data_access.append(DataAccess(resource=src, mode="DELETE", reason="mv source"))
        mode = "WRITE" if dst in self.existing else "CREATE"
        delta.data_access.append(DataAccess(resource=dst, mode=mode, reason="mv destination"))

    def _cmd_cp(self, args, delta):
        if len(args) < 2:
            delta.unknown.append("cp: could not parse source/destination")
            return
        src, dst = args[0], args[-1]
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
