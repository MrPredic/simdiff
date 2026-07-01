"""Shell adapter: a *conservative* safe interpreter for common mutating commands.

It never executes anything. It models a small, explicit set of mutating commands
(``rm``, ``rmdir``, ``mv``, ``cp``, ``mkdir``, ``touch``, ``chmod`` and
``>``/``>>`` redirects), a broader set of commands known to have **no** filesystem
effect regardless of their arguments (``ls``, ``grep``, ``git status``, ...), and
a pipeline of such commands (``a | b | c``). Anything it cannot fully account for
— a subshell, a variable or command substitution, a glob, an fd redirection,
backticks, backgrounding, unbalanced quotes, an unrecognized command, or a
pipeline containing one — is **fail-closed**: it goes into ``unknown`` and makes
the delta not ``fully_classified``. It must never pass an unmodelled construct
silently.

This is an interpreter of the request, not a simulation of the effect. It is only
trustworthy because it refuses to certify anything it does not fully understand.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Iterable, List, Optional, Set, Tuple

from ..delta import AuthorityGrant, CanonicalDelta, DataAccess

# Commands with no filesystem effect of their own (only via a redirect on their
# output, e.g. `echo x > file`).
_PRODUCERS = {"echo", "printf", "cat", "true", ":", "head", "tail"}

# Commands that never mutate the filesystem, *regardless of their arguments* —
# pure inspection/computation. Excluded on purpose: anything with a documented
# write-mode (`sort -o FILE`, `env CMD` running an arbitrary program) — those
# stay unmodelled rather than risk a false "no effect". `uniq` is handled
# separately below (its 2nd positional argument is an output file).
_READONLY_VERBS = _PRODUCERS | {
    # NOTE: `[` (the `test` alias) is deliberately not listed here: the bracket
    # is also how glob character-classes are spelled, and `_UNMODELLED` fails
    # closed on any `[`/`]` byte to be safe about globs — so `[ -f x ]` still
    # fails closed too. Disambiguating the two would need real quote-aware
    # parsing; `test -f x` (the non-bracket spelling) works today.
    "false", "test", "cd", "export",
    "ls", "pwd", "whoami", "date", "printenv", "hostname", "id", "uname", "nproc",
    "ps", "df", "du", "diff", "wc", "grep", "egrep", "fgrep", "which", "type",
    "sha256sum", "sha1sum", "md5sum", "file", "stat", "basename", "dirname",
    "realpath", "seq", "cut", "tr", "nl", "tac", "rev", "expr",
}

# `find` is read-only unless it carries an action flag that mutates or writes.
_FIND_MUTATING_FLAGS = {
    "-delete", "-exec", "-execdir", "-ok", "-okdir",
    "-fprint", "-fprint0", "-fprintf", "-fls",
}

# `git` subcommands that are pure reads in every invocation form. Deliberately
# excludes ones with a mutating form (`branch NAME`, `tag NAME`, `remote add`,
# `config key value`) — those stay unmodelled rather than risk a false negative.
_GIT_READONLY_SUBCOMMANDS = {
    "status", "log", "diff", "show", "rev-parse", "describe", "ls-files",
    "blame", "shortlog", "rev-list", "cat-file", "diff-tree", "name-rev",
    "check-ignore", "check-attr",
}

# split a command line into the individual commands we will look at
_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;|\n)\s*")

# shell metacharacters whose effect we do NOT model -> force fail-closed.
# (``&&``/``||``/``;`` are already removed by the split above, so a leftover
# ``&`` is backgrounding.) A leftover ``|`` is a pipe — handled structurally
# below, not here, because ``a | b`` is common and often fully modellable.
# ``[ ]`` are bracket (character-class) globs and ``{ }`` are brace expansion —
# both expand to a fileset we cannot enumerate, so they fail closed exactly like
# ``* ? ~``.
#
# Output redirects are only modelled when ``>`` / ``>>`` appear as their own
# whitespace-delimited tokens (``cmd > file``). A redirect *glued* to text
# (``cmd>file``, ``cmd>>file``, ``2>file``, ``&>file``) is valid bash but cannot
# be tokenised by ``shlex`` here, so it must fail closed rather than silently
# vanish: ``[^\s>]>`` is a ``>`` with a non-space char before it, ``>[^\s>]`` a
# ``>`` with a non-space, non-``>`` char after it. Clean ``a > b`` and ``a >> b``
# match neither.
_UNMODELLED = re.compile(r"[&$`<*?~{}\[\]]|[^\s>]>|>[^\s>]")


def _is_readonly(tokens: List[str]) -> bool:
    """True if this command (one pipeline stage, flags included) is known to
    have no filesystem effect, regardless of its arguments."""
    if not tokens:  # pragma: no cover - defensive; all callers pass non-empty stages
        return False
    verb = tokens[0]
    if verb == "find":
        return not any(t in _FIND_MUTATING_FLAGS for t in tokens[1:])
    if verb == "git":
        sub = next((t for t in tokens[1:] if not t.startswith("-")), None)
        return sub in _GIT_READONLY_SUBCOMMANDS
    if verb == "uniq":
        positional = [t for t in tokens[1:] if not t.startswith("-")]
        return len(positional) <= 1  # a 2nd positional is an output file
    return verb in _READONLY_VERBS


def _norm(path: str) -> str:
    return os.path.normpath(path)


class ShellAdapter:
    domain = "shell"

    def __init__(self, existing: Optional[Iterable[str]] = None):
        self.existing: Set[str] = {_norm(p) for p in (existing or ())}

    def simulate(self, action: str) -> List[str]:
        # "simulation" is purely lexical: split into raw command segments.
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
            if not tokens:  # pragma: no cover - defensive; non-blank segments tokenize non-empty
                continue
            stages = self._split_pipe(tokens)
            if stages is None:
                delta.unknown.append(f"malformed pipeline, cannot certify: {segment!r}")
                continue
            if len(stages) == 1:
                self._apply(stages[0], delta)
            else:
                self._apply_pipeline(stages, delta, segment)
        return delta

    # --- internals -------------------------------------------------------

    @staticmethod
    def _split_pipe(tokens: List[str]) -> Optional[List[List[str]]]:
        """Split on literal, whitespace-delimited ``|`` tokens (quoted ``|``
        chars stay glued to their token by ``shlex`` and are never split). A
        pipe with a missing stage (``a |``, ``| a``, ``a || `` already handled
        upstream) is malformed -> ``None``, which the caller fails closed on."""
        stages: List[List[str]] = []
        current: List[str] = []
        for t in tokens:
            if t == "|":
                if not current:
                    return None
                stages.append(current)
                current = []
            else:
                current.append(t)
        if not current:
            return None
        stages.append(current)
        return stages

    def _apply_pipeline(self, stages: List[List[str]], delta: CanonicalDelta, segment: str) -> None:
        """A pipeline is certified only if every stage is provably read-only —
        any mutating or unrecognized stage fails the whole pipeline closed. Only
        the last stage's output can be redirected to a file."""
        *head_stages, last = stages
        for stage in head_stages:
            if not _is_readonly(stage):
                delta.unknown.append(
                    f"unmodelled pipeline stage, cannot certify: {' '.join(stage)!r} in {segment!r}"
                )
                return
        tokens, redirects = self._strip_redirects(last)
        if tokens and not _is_readonly(tokens):
            delta.unknown.append(
                f"unmodelled pipeline stage, cannot certify: {' '.join(tokens)!r} in {segment!r}"
            )
            return
        for target, append in redirects:
            t = _norm(target)
            mode = "WRITE" if (append or t in self.existing) else "CREATE"
            delta.data_access.append(DataAccess(resource=t, mode=mode, reason="shell redirect (pipeline)"))

    def _apply(self, tokens: List[str], delta: CanonicalDelta) -> None:
        if not tokens:  # pragma: no cover - defensive; callers pass non-empty tokens
            return
        tokens, redirects = self._strip_redirects(tokens)
        for target, append in redirects:
            t = _norm(target)
            mode = "WRITE" if (append or t in self.existing) else "CREATE"
            delta.data_access.append(DataAccess(resource=t, mode=mode, reason="shell redirect"))
        if not tokens:
            return

        verb = tokens[0]
        # `cp -t DIR file` / `mv -t DIR file` copy INTO DIR; the flag takes a value
        # and inverts source/destination. Dropping it would hide the write to DIR,
        # so fail closed rather than misclassify. ``t`` is the only short flag cp/mv
        # spell with a lowercase ``t``, so any short-flag group containing it (``-t``,
        # ``-rt``, ``-vt`` ...) means target-directory; ``--target-directory=DIR`` is
        # a single token caught downstream by the arg-count check.
        if verb in ("cp", "mv") and any(
            a.startswith("-") and not a.startswith("--") and "t" in a[1:] for a in tokens[1:]
        ):
            delta.unknown.append(f"unmodelled flag (-t takes a value, inverts operands): {verb}")
            return

        args = [_norm(a) for a in tokens[1:] if not a.startswith("-")]
        handler = getattr(self, f"_cmd_{verb}", None)
        if handler is not None:
            handler(args, delta)
        elif _is_readonly(tokens):
            return  # no filesystem effect (effect, if any, was via redirect above)
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
        *srcs, dst = args  # `mv a b c dir` moves every source into the last operand
        for src in srcs:
            if src in self.existing:
                delta.data_access.append(DataAccess(resource=src, mode="DELETE", reason="mv source"))
        mode = "WRITE" if dst in self.existing else "CREATE"
        delta.data_access.append(DataAccess(resource=dst, mode=mode, reason="mv destination"))

    def _cmd_cp(self, args, delta):
        if len(args) < 2:
            delta.unknown.append("cp: could not parse source/destination")
            return
        *srcs, dst = args  # `cp a b c dir` copies every source into the last operand
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
