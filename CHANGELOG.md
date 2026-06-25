# Changelog

## 0.1.0

First release.

- `CanonicalDelta` effect model (value moves, authority grants, data access,
  resource use) with fail-closed `safe` semantics.
- Adapters: `FilesystemAdapter` (shadow-copy diff with content hashing),
  `SqlAdapter` (savepoint + rollback), `ShellAdapter` (safe interpreter, never
  executes).
- `simdiff(action, adapter)` top-level API and a demo CLI with fail-closed exit
  codes.
- Adversarial benchmark (`python -m bench.run`): on a 14-case obfuscated-effect
  corpus, effect simulation catches 100% at 0% false positives vs 25% for
  keyword/argument scanning. Numbers are asserted in CI.
- Zero runtime dependencies, MIT licensed, typed (`py.typed`).
