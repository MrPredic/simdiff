# Contributing to simdiff

Thanks for considering a contribution. simdiff is a small, security-focused
library, so a few conventions are non-negotiable — they're what makes it
trustworthy.

## Ground rules

1. **Fail-closed always.** Anything an adapter cannot fully account for goes into
   `unknown` (which makes `delta.fully_classified` `False`). A change that lets an
   effect be reported as classified when it isn't will be rejected. When in doubt,
   fail closed.
2. **Zero runtime dependencies.** The library uses only the Python standard
   library. Test/dev tools (pytest, hypothesis, coverage) are fine; a runtime
   dependency is not.
3. **Test-driven.** Write the failing test first, watch it fail, then implement.
   Bug fixes start with a test that reproduces the bug.
4. **100% coverage is enforced** (`--cov-fail-under=100`, statement + branch).
   Cover new branches or mark genuinely unreachable defensive code with
   `# pragma: no cover` and a reason.

## Development setup

```bash
git clone https://github.com/MrPredic/simdiff
cd simdiff
pip install -e .
pip install pytest pytest-cov hypothesis     # dev tools

python -m pytest -q --cov --cov-fail-under=100   # full suite + coverage gate
python -m bench.run                              # adversarial benchmark
```

## Adding a domain adapter

An adapter is a class with two methods and a `domain` string:

```python
class MyAdapter:
    domain = "mydomain"

    def simulate(self, action) -> Effect:        # dry-run; never mutate the real target
        ...

    def extract_delta(self, effect, principal=None) -> CanonicalDelta:
        ...                                        # express the effect; unknowns -> fail closed
```

- Decide whether you **simulate** (execute & observe, like `sql`/`filesystem`) or
  **interpret** (parse the request, like `shell`/`http`). Document which, and if
  you execute the action, say so in `SECURITY.md`.
- Add tests under `tests/test_<domain>_adapter.py`, plus fail-closed cases in
  `tests/test_hardening.py` and invariants in `tests/test_properties.py`.

## Pull requests

- Keep changes focused; one concern per PR.
- Run the full suite, the coverage gate, and the benchmark before opening.
- Update `CHANGELOG.md` under the unreleased/most-recent section.
- Describe the security reasoning: what effect is now seen, or what stays
  fail-closed.

## Reporting security issues

Don't open a public issue for a vulnerability — see [`SECURITY.md`](SECURITY.md).
