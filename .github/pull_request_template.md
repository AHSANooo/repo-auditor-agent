## Summary

<!-- One-paragraph description of what this PR does and why. -->

## Type of Change

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 🔒 Security improvement
- [ ] ♻️ Refactor (no functional change)
- [ ] 📝 Documentation update
- [ ] 🧪 Tests only
- [ ] ⚙️ CI / DevOps

## Related Issue

Closes #<!-- issue number -->

## Changes

<!-- Bullet-point list of specific changes made. -->

- 
- 

## Testing

<!-- Describe how you tested this change. -->

- [ ] All existing tests pass (`pytest tests/ -v`)
- [ ] New tests added for new behaviour
- [ ] Coverage remains ≥ 80% (`pytest --cov-fail-under=80`)
- [ ] `ruff check .` passes
- [ ] `ruff format --check .` passes
- [ ] `mypy src/` passes with zero errors

## Security Checklist

<!-- For any change that touches agent behaviour, tools, or secret handling: -->

- [ ] No raw secrets in evidence or logs
- [ ] Path traversal sandbox not weakened
- [ ] No `shell=True` introduced in subprocess calls
- [ ] `.env` or credential files not committed

## Screenshots / Sample Output

<!-- If relevant, show before/after output or report JSON snippets. -->
