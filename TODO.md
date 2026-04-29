# TODO

## Drift Detection as a GitHub Action

**Problem:** Drift detection currently lives in the plugin daemon. The plugin compares PCE active policy vs Git YAML in memory and exposes it via `/api/drift`. This means:
- Drift is invisible unless the plugin is running and its dashboard is watched
- GitHub Actions have no visibility into drift state
- The plugin may not be reachable from GitHub-hosted runners

**Solution:** Replace (or complement) plugin-based drift detection with a scheduled GitHub Action (`drift-check.yml`) that:

1. Checks out the repo (Git state)
2. Connects to PCE directly using the same secrets already configured (`PCE_HOST`, `PCE_API_KEY`, etc.)
3. Runs a Python script (`drift-check.py`) that compares PCE active policy vs YAML files in `scopes/`, `ip-lists/`, `services/`
4. If drift is found:
   - Opens a GitHub Issue summarising drifted objects, OR
   - Triggers an export (creates a PR with the delta) so the team can review and merge

**Benefits:**
- No plugin reachability required
- Drift is visible in GitHub Issues / PRs — actionable by anyone with repo access
- Runs on a cron schedule (e.g. daily) independent of the plugin

**Notes:**
- The drift-check script can reuse the `DriftDetector` logic from `plugin/main.py` — extract it into `action/scripts/drift-check.py`
- The workflow should skip opening a duplicate issue if one is already open with the same label
- Consider making the workflow also triggerable via `workflow_dispatch` for on-demand checks
