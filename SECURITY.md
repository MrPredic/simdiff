# Security model

simdiff turns a proposed action into a structured **effect delta** that a policy
can decide on. It is a building block, not a complete defense. Understand these
properties before relying on it.

## What it gives you

- A canonical description of an action's effect (value moves, authority grants,
  data access, egress), so your policy decides over the *effect*, not the request.
- **Fail-closed** classification: anything an adapter cannot fully account for
  goes into `unknown` and makes `delta.fully_classified` `False`. Treat that as
  block / escalate.

## What it does NOT give you

- **`fully_classified` is not a safety verdict.** It means "the effect was
  understood", not "the action is safe". A fully-classified delta can be a
  destructive delete or an exfiltration. The allow/block decision is yours.
- **It is not a sandbox.** The `filesystem` and `sql` adapters **execute the
  action** to observe its effect:
  - `filesystem` runs the supplied callable against a copied directory. The copy
    only protects the original directory — the callable can still touch absolute
    paths, the network, or anything else the process can.
  - `sql` runs the statement inside a savepoint and rolls back row changes. Side
    effects (triggers, `load_extension`, files written by extensions) are **not**
    undone.
  - **Mitigation:** run simdiff inside your own isolation (container, VM, seccomp,
    unprivileged user) whenever the action is untrusted.
- **`shell` / `http` interpret the request; they do not simulate.** They are
  conservative and fail closed on anything unmodelled, so they tend to produce
  many false positives on real workloads — that is the intended trade-off, but it
  is not zero-false-positive in practice.
- **The `shell` adapter drops flags it does not model.** Flags that take a value
  and *invert* operands (`cp -t DIR` / `mv -t DIR`) are detected and fail closed.
  Other value-taking flags (`mkdir -m MODE`, `touch -r REF`) are dropped, which can
  add a spurious operand to the delta (a false positive, never a hidden effect).
- **The `shell` adapter trusts `existing` as ground truth.** A `DELETE`/`mv`-source
  on a path you did not list in `existing` is treated as a no-op (the file is
  assumed not to exist), so it produces no delta and stays `fully_classified`.
  If `existing` is incomplete relative to the real filesystem, a real deletion can
  be invisible. **Mitigation:** populate `existing` from the actual sandbox listing,
  not a guess.
- **`solana` only inspects accounts you pass in `watch`.** Effects on accounts you
  did not enumerate are invisible. An *empty* `watch` fails closed (it certifies
  nothing), but a non-empty-but-incomplete `watch` does not — list every account
  the transaction can touch. Pre- and post-state come from two RPC calls and may
  be a slot apart.

## Reporting a vulnerability

Open a GitHub issue, or for sensitive reports use the repository's private
vulnerability reporting. Please include a minimal reproduction.
