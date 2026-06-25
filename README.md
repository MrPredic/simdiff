# simdiff

**The effect layer for AI-agent firewalls.** Simulate an action, get back a
canonical, structured **effect delta** — *what would actually change* — and let
your policy engine decide on that instead of on the raw tool call.

```python
from simdiff import simdiff
from simdiff.adapters.shell import ShellAdapter

delta = simdiff("rm important.db", ShellAdapter(existing={"important.db"}))
print(delta.to_dict())
# {'data_access': [{'resource': 'important.db', 'mode': 'DELETE', ...}],
#  'unknown': [], 'safe': True, ...}
```

## Why it exists

The 2026 wave of pre-execution agent firewalls — [AEGIS](https://arxiv.org/abs/2603.12621),
OAP / Open Agent Passport, Agent Action Guard,
[*Before the Tool Call*](https://arxiv.org/abs/2603.20953) — all decide **before**
a tool runs. But they decide over the **request**: the tool name and its
arguments, which they scan. An argument can look benign while the real effect is
destructive.

simdiff is **not** another firewall. It is the missing piece they share: it
**simulates** the action and returns its **canonical effect**, so a policy can
decide over *the verified effect, not the request*. It composes with those tools
rather than competing with them.

## Design principles

- **Deterministic** — no LLM, no network, no cloud, no API keys in the core.
- **Fail-closed** — anything an adapter cannot classify lands in `unknown`, which
  makes the whole delta `safe == False`.
- **No real mutation** — filesystem uses a shadow copy, SQL uses rollback, shell
  is interpreted and never executed.
- **Zero runtime dependencies** — pure Python standard library.

## The effect delta

```
CanonicalDelta
  value_moves[]       asset transfers (asset, src, dst, amount)
  authority_grants[]  permission / owner / mode changes
  data_access[]       CREATE | WRITE | DELETE | READ  (+ bytes)
  resource_use        coarse io / row counts
  unknown[]           unclassifiable effects  ->  fail-closed
  safe                False iff unknown is non-empty
```

## Adapters

| Adapter | Action | How it simulates | Never mutates because |
|---|---|---|---|
| `FilesystemAdapter(sandbox)` | a callable `action(root)` | runs it on a **shadow copy**, diffs before/after | works on a tempdir copy |
| `SqlAdapter(connection)` | a SQL statement | runs inside `SAVEPOINT … ROLLBACK` | always rolls back |
| `ShellAdapter(existing=…)` | a command line | **interprets** `rm`/`mv`/`cp`/`mkdir`/`touch`/`chmod`/redirects | never executes |

Adding a domain = implement two methods (`simulate`, `extract_delta`). A Solana
`simulateTransaction` adapter and an HTTP adapter are natural next steps.

## CLI

```bash
simdiff shell "rm a.txt && mkdir b" --existing a.txt --json
simdiff sql   "DELETE FROM users WHERE id = 1" --db app.sqlite
```

Exit code is fail-closed: `0` when the delta is safe, `2` otherwise — usable as a
gate in a pipeline (the real decision still belongs to your policy).

## Install

```bash
pip install -e .
python -m pytest -q
```

See [`examples/firewall_integration.py`](examples/firewall_integration.py) for a
policy deciding over the effect.

## License

MIT
