# simdiff

**The effect layer for AI-agent firewalls.** Simulate an action, get back a
canonical, structured **effect delta** — *what would actually change* — and let
your policy engine decide on that instead of on the raw tool call.

> On a small **illustrative** corpus, deciding over the effect catches every
> obfuscated attack that argument keyword-matching misses (the constructs change
> the surface text but not the effect). It demonstrates the *principle*, not
> production numbers — read [Security model & limitations](#security-model--limitations)
> before trusting it. ([reproduce](#benchmark): `python -m bench.run`)

```python
from simdiff import simdiff
from simdiff.adapters.shell import ShellAdapter

delta = simdiff("rm important.db", ShellAdapter(existing={"important.db"}))
print(delta.to_dict())
# {'data_access': [{'resource': 'important.db', 'mode': 'DELETE', ...}],
#  'unknown': [], 'fully_classified': True, ...}   # classified != safe: this DELETES the file
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

The line: everyone else canonicalizes or scans the *request*. simdiff reports the
*effect*. The adapters do this two different ways — be clear which you are using:

- **Simulate (execute & observe):** `filesystem` (runs the action on a shadow
  copy), `sql` (runs inside a rollback), `solana` (RPC `simulateTransaction`).
  These see the *real* effect — but they **execute the action**. See the security
  model below.
- **Interpret the request (no execution), fail-closed:** `shell`, `http`. These
  do *not* observe a real effect; they parse what the request would do and refuse
  to certify anything they can't fully model. They are only trustworthy because
  they fail closed, not because they simulate.

## What simdiff is NOT

- Not a policy engine — it returns the effect; **you** (or your firewall) decide.
- Not a complete agent-security solution — it is one composable building block.
- `fully_classified` is **not** a safety verdict (see below).

## Design principles

- **Fail-closed** — anything an adapter cannot account for lands in `unknown`,
  which makes `delta.fully_classified` `False`. Treat that as block/escalate.
- **`fully_classified` ≠ safe** — it only means the effect was *understood*. A
  fully-classified delta can still be a destructive `DELETE` or an exfil. The
  allow/block decision is the consumer's.
- **Deterministic** — no LLM in the decision path. The `filesystem`, `sql`,
  `shell`, and `http` adapters are offline; `solana` is the one that needs an RPC.
- **Zero runtime dependencies** — pure Python standard library (Solana RPC uses
  `urllib`, no `solana-py` needed).

## Security model & limitations

Read this before putting simdiff in front of an agent. It is honest about what it
does and does not protect.

- **The simulate-adapters execute the action.** `filesystem` runs the supplied
  callable (it can touch absolute paths, the network, anything — the shadow copy
  only protects the *sandbox dir*, it is **not** a sandbox). `sql` runs the
  statement (triggers, `load_extension`, etc. run for real; rollback only undoes
  row changes). **Run simdiff inside your own isolation (container / VM / seccomp)
  when the action is untrusted.** simdiff does not sandbox.
- **`shell`/`http` are conservative parsers, not simulators.** They fail closed on
  anything unmodelled (pipes, subshells, `$VAR`, globs, fd redirects, unknown
  commands → `unknown`). That means on real-world command streams they will flag a
  *lot* (e.g. `git`, `python`, `docker`, any pipe) — by design. Low false-negative,
  high false-positive. Don't read the benchmark's 0% FP as a real-world number.
- **`solana` only sees accounts you list in `watch`.** A drain to an account you
  didn't enumerate is invisible. Pre-state and simulated post-state come from two
  RPC calls and may be one slot apart.
- **Policy matching is the consumer's job.** The bundled example policy compares
  resource names literally — normalize paths/hosts yourself before matching.

## The effect delta

```
CanonicalDelta
  value_moves[]       asset transfers (asset, src, dst, amount)
  authority_grants[]  permission / owner / mode changes
  data_access[]       CREATE | WRITE | DELETE | READ  (+ bytes)
  resource_use        coarse io / row counts
  unknown[]           unclassifiable effects  ->  fail-closed
  fully_classified    False iff unknown is non-empty (classification, NOT safety)
```

## Adapters

| Adapter | Action | Mechanism | Executes the action? |
|---|---|---|---|
| `FilesystemAdapter(sandbox)` | a callable `action(root)` | runs it on a **shadow copy** of the dir, diffs before/after | **yes** — isolate untrusted actions yourself |
| `SqlAdapter(connection)` | a SQL statement | runs inside `SAVEPOINT … ROLLBACK` | **yes** — row changes roll back, side effects don't |
| `ShellAdapter(existing=…)` | a command line | **interprets** `rm`/`mv`/`cp`/`mkdir`/`touch`/`chmod`/redirects; fail-closed on anything else | no |
| `HttpAdapter(allowed_hosts=…)` | an `HttpRequest` | classifies **egress** (bytes leaving for a non-allowed host) | no — never sends |
| `SolanaAdapter(rpc_url=…)` | a `SolanaTransaction` | RPC `simulateTransaction` + account diff → SOL/token deltas, delegate/owner changes | no — simulated on a node, never broadcast |

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

Exit code reflects **classification, not safety**: `0` when the delta is
`fully_classified`, `2` otherwise. `0` does **not** mean "allowed" — `rm prod.db`
exits `0` because it was understood. The allow/block decision belongs to your policy.

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

**Honest caveats:** this is a small, hand-built corpus that I wrote — it
illustrates *that effect-deciding beats text-matching on obfuscation*, it is not a
general benchmark against production firewalls (which do far more than keyword
denylisting). The **0% false-positive figure is corpus-specific**: the safe cases
use only commands the shell adapter models. On real command streams the adapter
fail-closes on most input (`git`, `python`, pipes, …), so real-world false
positives are *high*, not zero. The signal to take away is the *direction*, not
the percentages.

## Install

```bash
pip install -e .
python -m pytest -q
```

See [`examples/firewall_integration.py`](examples/firewall_integration.py) for a
policy deciding over the effect.

## License

MIT
