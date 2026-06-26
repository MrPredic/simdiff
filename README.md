# simdiff

**The effect layer for AI-agent firewalls.** Simulate an action, get back a
canonical, structured **effect delta** — *what would actually change* — and let
your policy engine decide on that instead of on the raw tool call.

> On an adversarial corpus of obfuscated-effect attacks, deciding over the
> **simulated effect catches 100%** of them at **0% false positives** — while
> keyword/argument scanning catches **27%**. ([reproduce](#benchmark): `python -m bench.run`)

```python
from simdiff import simdiff
from simdiff.adapters.shell import ShellAdapter

delta = simdiff("rm important.db", ShellAdapter(existing={"important.db"}))
print(delta.to_dict())
# {'data_access': [{'resource': 'important.db', 'mode': 'DELETE', ...}],
#  'unknown': [], 'safe': True, ...}
```

## Where it sits

```
agent proposes action ─▶ [ simdiff: simulate ▶ canonical effect delta ] ─▶ your policy ─▶ ALLOW / BLOCK / APPROVE ─▶ real execution
```

simdiff owns exactly one box: turning a proposed action into *what it would
actually do*. The decision and the execution stay yours.

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

## How it compares

| Tool | Decides over | Form |
|---|---|---|
| agent-airlock, MS agent-governance-toolkit, Faramesh | the **call** (tool name + args, normalized/validated) | full firewall / control plane |
| AEGIS, OAP, Agent Action Guard | the **call** (extract + scan args) before execution | full firewall |
| **simdiff** | the **simulated effect** (what would actually change) | a **library / primitive** you feed to any of the above |

The line: everyone else canonicalizes or scans the *request*. simdiff canonicalizes
the *result of simulating it*. An argument can lie about what it does; a simulated
effect cannot.

## What simdiff is NOT

- Not a policy engine — it returns the effect; **you** (or your firewall) decide.
- Not a sandbox or a runtime — it never executes the real action.
- Not a complete agent-security solution — it is one composable building block.

## Design principles

- **Deterministic & offline** — no LLM, no cloud, no API keys. The four core
  adapters never touch the network. (The optional Solana adapter is the one
  exception: only a node can know a transaction's effect, so it calls an RPC
  endpoint you provide — see below.)
- **Fail-closed** — anything an adapter cannot classify lands in `unknown`, which
  makes the whole delta `safe == False`.
- **No real mutation** — filesystem uses a shadow copy, SQL uses rollback, shell
  is interpreted, HTTP is parsed, Solana is simulated — none execute/send/broadcast.
- **Zero runtime dependencies** — pure Python standard library (Solana RPC uses
  `urllib`, no `solana-py` needed).

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
| `HttpAdapter(allowed_hosts=…)` | an `HttpRequest` | classifies **egress** (bytes leaving for a non-allowed host) | never sends |
| `SolanaAdapter(rpc_url=…)` | a `SolanaTransaction` | RPC `simulateTransaction` + account diff → SOL/token deltas, delegate/owner changes | never broadcasts (online) |

Adding a domain = implement two methods (`simulate`, `extract_delta`).

### Solana / on-chain (the high-stakes domain)

A transaction can read like "swap 5 USDC" while its real effect is "assign a
permanent delegate that drains the token account". Instruction inspection misses
that; simulation does not.

```python
from simdiff import simdiff
from simdiff.adapters.solana import SolanaAdapter, SolanaTransaction

adapter = SolanaAdapter(rpc_url="https://api.mainnet-beta.solana.com")
delta = simdiff(SolanaTransaction(tx_b64, watch=[my_token_account]), adapter)
# value_moves: [SPL:… 1000000 my_acct -> (outflow)]
# authority_grants: [delegate none -> <attacker> (drain risk)]
```

This is the only adapter that uses the network — there is no local way to know a
transaction's on-chain effect. The RPC call is injectable for offline testing,
and the default uses `urllib` only. See [`examples/solana_drain.py`](examples/solana_drain.py).

## CLI

```bash
simdiff shell "rm a.txt && mkdir b" --existing a.txt --json
simdiff sql   "DELETE FROM users WHERE id = 1" --db app.sqlite
```

Exit code is fail-closed: `0` when the delta is safe, `2` otherwise — usable as a
gate in a pipeline (the real decision still belongs to your policy).

## Benchmark

Why "decide over the effect, not the request" is not just a slogan:

```
$ python -m bench.run
corpus: 18 cases (11 dangerous, 7 safe)

approach                  recall   false positives
--------------------------------------------------
effect simulation (simdiff)      100%                0%
keyword/arg scanning         27%                0%
```

The corpus pits the same dangerous effect against argument obfuscation:
deletion expressed as `mv prod.db /dev/null`, `DROP/**/TABLE` split by a SQL
comment, permission widening via symbolic `chmod u=rwx,go=rwx`, destruction
through an uninterpreted tool (`find … -delete`, caught **fail-closed**), and a
secret exfiltrated as a **base64** body or a query parameter — invisible to
payload scanning, but the destination host gives it away. Each preserves the
effect while changing the surface text, so keyword scanning waves it through and
effect simulation does not. The baseline is a *reasonable*, case-insensitive
denylist (it even greps for plaintext key markers) — not a strawman; its
weakness is structural.

These numbers are asserted in [`tests/test_benchmark.py`](tests/test_benchmark.py),
so the claim cannot drift from the code. See [`bench/corpus.py`](bench/corpus.py)
for every case.

## Install

```bash
pip install -e .
python -m pytest -q
```

See [`examples/firewall_integration.py`](examples/firewall_integration.py) for a
policy deciding over the effect.

## License

MIT
