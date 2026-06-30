<!-- Keep PRs focused: one concern each. -->

## What & why

<!-- What effect is now seen, or what stays fail-closed, and why. -->

## Checklist

- [ ] Tests added first and watched fail (TDD); bug fixes include a reproducing test
- [ ] `python -m pytest -q --cov --cov-fail-under=100` passes (100% statement + branch)
- [ ] `python -m bench.run` unchanged (or the change is explained)
- [ ] No new runtime dependency (stdlib only)
- [ ] Fail-closed preserved — nothing newly reported as classified that isn't fully understood
- [ ] `CHANGELOG.md` updated
