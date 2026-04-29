# Contributing

## Versioning

Components are versioned independently using **semver** (`MAJOR.MINOR.PATCH`).

| Component | File |
|-----------|------|
| Export/provision plugin | `plugin/plugin.yaml` |
| Workflow plugin | `workflow/plugin.yaml` |
| Pipeline scripts | `action/scripts/` (version in `plugin/plugin.yaml`) |
| Repo template | `template/` (version in `plugin/plugin.yaml`) |

### When to bump

| Change | Bump |
|--------|------|
| Bug fix, log improvement, no behaviour change | `PATCH` |
| New feature, new config option, new security rule | `MINOR` |
| Breaking change: YAML format, removed config, API response change | `MAJOR` |

Default on every PR merge: **MINOR** unless the PR is clearly a bug fix (PATCH) or explicitly breaking (MAJOR).

### How to release

```bash
# 1. Update version in plugin/plugin.yaml and workflow/plugin.yaml
# 2. Commit
git commit -m "chore: bump version to X.Y.Z"

# 3. Tag and push
git tag vX.Y.Z
git push origin vX.Y.Z

# 4. Create GitHub release
gh release create vX.Y.Z --title "vX.Y.Z" --generate-notes
```

## Pull Requests

- One logical change per PR
- Title format: `type: description` (`feat:`, `fix:`, `chore:`, `docs:`)
- Sync changes to both `action/scripts/` and the working repo's `.github/scripts/` when modifying pipeline scripts
- Sync workflow changes to both `template/.github/workflows/` and the working repo's `.github/workflows/`

## Repository Layout

```
plugin/          Export plugin (runs as a plugger daemon, exports PCE → Git)
workflow/        Workflow plugin (approval/reconcile endpoints)
action/scripts/  Pipeline scripts (validate, provision, traffic evidence, etc.)
template/        Starter repo template (.github/workflows, CODEOWNERS, etc.)
```
