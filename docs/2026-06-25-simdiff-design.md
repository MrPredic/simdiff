# simdiff — Design

**Date:** 2026-06-25 · **Status:** historical design snapshot

> Note: this is the original design. Since 0.2.0 the `safe` field is named
> `fully_classified` (it reports classification, not a safety verdict), and the
> `shell`/`http` adapters fail closed on anything unmodelled. See README +
> SECURITY.md for current behavior.

## Problem

The 2026 wave of pre-execution agent firewalls — **AEGIS** (arXiv 2603.12621, MIT),
**OAP / Open Agent Passport**, **Agent Action Guard**, *"Before the Tool Call"*
(arXiv 2603.20953) — all decide **before** a tool runs. But they decide over the
**request**: the tool name and its arguments, which they extract and scan. None of
them **simulate the action and bind the decision to the action's actual, canonical
effect.** That gap is obfuscation-prone: an argument can look benign while the real
effect is destructive.

`simdiff` fills exactly that gap. It is **not** another firewall. It is the missing
**effect layer**: simulate an action via a domain adapter, return a canonical,
structured **effect delta** ("what would actually change"), and hand it to whatever
policy/firewall already makes the decision.

## Non-goals (the differentiation discipline)

- No policy engine, no allow/block decision — that is the firewall's job.
- No LLM, no network, no cloud, no API keys in the core.
- No real mutation of the target system.

We produce the delta. Consumers decide. Clean boundary = the wedge.

## Core data model — `CanonicalDelta`

```
CanonicalDelta
  value_moves[]       ValueMove(asset, src, dst, amount, reason)
  authority_grants[]  AuthorityGrant(target, kind, old, new, reason)   # e.g. file mode, owner
  data_access[]       DataAccess(resource, mode, bytes, reason)        # mode: CREATE|WRITE|DELETE|READ
  resource_use        ResourceUse(io_bytes, rows, ...)
  unknown[]           list[str]   # anything an adapter could not classify
  safe                bool        # False iff unknown is non-empty (fail-closed)
```

Every entry carries a human-readable `reason` (provenance). `to_dict()` yields the
JSON artifact a firewall consumes.

## Adapter protocol

```python
class Adapter(Protocol):
    domain: str
    def simulate(self, action) -> Effect: ...                 # adapter holds its own context
    def extract_delta(self, effect, principal=None) -> CanonicalDelta: ...
```

Each adapter receives its domain context in its constructor
(`FilesystemAdapter(sandbox)`, `SqlAdapter(connection)`, `ShellAdapter(existing)`),
so `simulate` takes only the action.

Top-level convenience:

```python
def simdiff(action, adapter, *, principal=None) -> CanonicalDelta
```

## Reference adapters (offline, stdlib-only, real simulation)

1. **FilesystemAdapter** — copies the sandbox dir to a tempdir, runs the action
   (a callable) against the **shadow copy**, snapshots before/after, diffs.
   → `data_access` (CREATE/WRITE/DELETE + byte deltas), `authority_grants` (mode
   changes). The original directory is never touched.

2. **SqlAdapter** — runs the statement inside `BEGIN … ROLLBACK` against a sqlite3
   connection, captures affected tables/rowcounts. → `data_access` per table.
   The database is never mutated.

3. **ShellAdapter** — a **safe interpreter** (no execution) for common mutating
   commands: `rm`, `mv`, `cp`, `mkdir`, `rmdir`, `touch`, `chmod`, and `>`/`>>`
   redirects. Resolves them against a directory snapshot into a predicted delta.
   Anything it cannot parse → `unknown` → `safe = False`.

## Guarantees

- **Deterministic** — no LLM, no network in the core.
- **Fail-closed** — unclassifiable effect ⇒ `unknown` populated, `safe = False`.
- **No real mutation** — FS shadow copy; SQL rollback; Shell never executes.
- **Zero runtime deps** — `json`, `sqlite3`, `tempfile`, `shutil`, `filecmp`, `shlex`, `os`.
- **MIT**.

## Repo layout

```
src/simdiff/
  __init__.py            # simdiff(), CanonicalDelta + types, adapters re-export
  delta.py               # CanonicalDelta + entry dataclasses + to_dict
  adapters/
    base.py              # Adapter protocol, Effect
    filesystem.py
    sql.py
    shell.py
  cli.py                 # demo CLI
tests/                   # TDD, one file per unit
examples/firewall_integration.py
README.md  pyproject.toml  LICENSE  .github/workflows/test.yml
```

## Testing (TDD — tests first)

- **delta:** construction; `safe` flips False when `unknown` present; `to_dict`
  round-trip; merge of two deltas.
- **filesystem:** create→WRITE+bytes; delete→DELETE; chmod→authority_grant;
  original dir unchanged; callable raising → `unknown`, `safe=False`.
- **sql:** INSERT→WRITE+rowcount; DELETE→DELETE; DB unchanged after (rollback);
  unparseable stmt → `unknown`.
- **shell:** `rm`/`mv`/`cp`/`mkdir`/`chmod`/redirect → correct deltas; unknown
  command → `unknown`, `safe=False`.
