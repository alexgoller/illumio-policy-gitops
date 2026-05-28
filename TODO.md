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

## Provider-Centric Cross-Scope Authoring

**Problem:** Cross-scope dependencies originally required authoring **two** files — a
requester-side `cross-scope/to-<target>.yaml` and a target-side
`inbound/from-<requester>.yaml`. This was redundant:
- The requester-side file was never provisioned (it has no `rules:`, so `provision.py` skips it) — it was pure documentation.
- Illumio scopes are **provider-centric**: an extra-scope rule protects the provider's workloads, so the canonical rule belongs in the provider's scope. The requester-side file added authoring toil and a mirror to keep in sync, with no policy value.

**Solution:** Author the cross-scope rule **once** in the provider's scope; generate the requester-side view.

1. Canonical rule lives at `scopes/app-<provider>_env-<env>/inbound/from-<requester>.yaml` (standard ruleset schema, `unscoped_consumers: true`). The provider team + security own/approve it via CODEOWNERS on `inbound/`; the requester is the PR author.
2. `action/scripts/generate-cross-scope-docs.py` derives the read-only requester-side `cross-scope/to-<provider>.yaml` (carries `generated: true`, never provisioned, skipped by security checks). Regenerated + committed on merge by `provision-policy.yml`.
3. `SEC-010` enforces the model: extra-scope rules must be authored in the provider's scope (providers in-scope, consumers external), and the deprecated `requester:`/`target:` schema is flagged.

**Benefits:**
- One file to author, no redundant mirror to keep in sync.
- Approval falls out of the data model: the provider (whose workloads are reached) approves; the requester just opens the PR.
- Requester-side discoverability preserved via the generated view.

**Notes:**
- Justification metadata (`justification`, `requested_by`, `requested_date`) now lives on the canonical inbound file (also fixes a latent SEC-004 warning that fired on inbound files lacking justification).
- Requester environment is assumed to match the provider's; revisit if cross-env dependencies are needed.
- Implemented in this change — kept here as the design record.

## Provision Net-New Services to the PCE (Git → PCE)

**Problem:** `provision.py` only routed `ip-lists/` and `scopes/`. A net-new named service
authored in Git under `services/` was never created on the PCE, and any rule referencing it
by name failed resolution — a hole in the "Git is the source of truth" story.

**Solution (implemented in this change):** Added `provision_service` (create/update by name
against the PCE draft), routed `services/` in `main()`, ordered services before rulesets, and
refreshed the service cache so rules resolve newly-created services. Service deletions handled
in `delete_object`.

**Notes:**
- Follow-up: `plugin/main.py`'s `import_yaml_to_*` functions are dead code — the daemon's `SYNC_MODE=provision` never wires to a Git→PCE write path (only `provision.py` in the Action does). Decide whether to wire it or remove the dead converters.
