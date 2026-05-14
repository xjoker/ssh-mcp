<!--
Thanks for the PR. Please make sure of the following before requesting review:

- [ ] `go test -race ./...` passes locally
- [ ] `bash scripts/check-deps.sh` passes (module-boundary allowlist updated if you added a new internal/ → internal/ import)
- [ ] CHANGELOG.md updated under `[Unreleased]` if user-visible
- [ ] README (EN + ZH) updated if user-facing
- [ ] No secret material in commits / commit messages
-->

## Summary

<!-- 1-3 sentences. What does this change do, and why? -->

## Type of change

- [ ] Bug fix (no behaviour change for callers)
- [ ] New feature (additive, no breakage)
- [ ] Breaking change (callers must adapt; explain in CHANGELOG `### Breaking`)
- [ ] Documentation only
- [ ] CI / build only

## Test plan

<!-- How did you verify? Commands run, what they showed. New tests added? -->

## Related issues

<!-- e.g. "closes #123" -->
