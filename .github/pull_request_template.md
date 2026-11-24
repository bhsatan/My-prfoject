## Description

<!-- Briefly describe what this PR does and why. -->

## Checklist

- [ ] **Read-only confirmed**: No code writes, modifies, or deletes system state.
- [ ] **No network added**: No new outbound calls, listeners, or telemetry in the core engine.
- [ ] **Tests added**: New behaviour is covered by unit tests using mocked facts/output.
- [ ] **Tests pass on any OS**: Tests do not depend on real system state.
- [ ] **Rule sources cited**: Every rule references a real, verifiable source.
- [ ] **No `shell=True`**: All subprocess calls use argument lists.
- [ ] **No secrets**: No hardcoded keys, tokens, or credentials.
- [ ] **Type hints**: All new function signatures include type hints.

## Type of Change

- [ ] New feature (non-breaking change that adds functionality)
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] Documentation update
- [ ] Test improvement
- [ ] CI / build change
- [ ] Refactor (no functional change)
