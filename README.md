# Illumio Policy GitOps

**Policy-as-code for Illumio PCE — peer review, traffic evidence, security validation, and automated provisioning through your existing Git workflow.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Plugin Version](https://img.shields.io/badge/plugin-v0.2.0-green?style=flat-square)](plugin/plugin.yaml)
[![Workflow Version](https://img.shields.io/badge/workflow-v0.2.0-green?style=flat-square)](workflow/plugin.yaml)

---

## What Is This?

Illumio PCE has a robust draft/active policy model and an event log that records who provisioned what. For single-team environments, that's often enough. But as organizations grow — multiple application teams, cross-scope rules, compliance audits, ITSM change control — the PCE's native capabilities leave gaps:

- **No peer review gate.** Any engineer with API access can create a rule and provision it to active.
- **No cross-team coordination.** Team A can write rules into Team B's scope without Team B knowing.
- **Incomplete audit trail.** PCE events show *who clicked provision*, not *who reviewed and approved*.
- **No rollback mechanism.** Reverting a bad rule means manual GUI edits under pressure.
- **GUI changes bypass everything.** Engineers editing directly in the PCE bypass any process you build.

This project closes those gaps by treating segmentation policy as code — version-controlled, peer-reviewed, automatically validated, and deployed through a repeatable pipeline.

---

## Two Components, One Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ILLUMIO PCE                                     │
│                    (Draft / Active Policy)                               │
└───────────────┬─────────────────────────────────────────┬───────────────┘
                │  Export (PCE → Git)                      │  Provision (Git → PCE)
                ▼                                          │
┌───────────────────────────────┐                          │
│     POLICY GITOPS PLUGIN      │──── pulls from ──────────┘
│   (plugger daemon container)  │
└───────────────────────────────┘
                │  commits YAML
                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        POLICY REPOSITORY (Git)                          │
│                                                                         │
│  scopes/                  ip-lists/          services/                  │
│  ├── _global/             ├── rfc1918.yaml    ├── postgresql.yaml       │
│  ├── app-payments_env-prod/  └── zscaler.yaml └── https.yaml           │
│  │   ├── _scope.yaml                                                    │
│  │   ├── intra-rules.yaml                                               │
│  │   └── cross-scope/to-shareddb.yaml                                  │
│  └── app-shareddb_env-prod/                                             │
│      ├── _scope.yaml                                                    │
│      └── inbound/from-payments.yaml                                     │
└───────────────────────┬─────────────────────────────────────────────────┘
                        │  Pull Request
                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      GITHUB ACTIONS PIPELINE                            │
│                                                                         │
│  ① YAML lint   ② Security checks (8 rules)   ③ Traffic evidence       │
│  ④ Policy resolution   ⑤ Firewall change request   ⑥ PR comment       │
│                                                                         │
│  CODEOWNERS enforces: payments-team + database-team + security-team     │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                       POLICY WORKFLOW PLUGIN                            │
│              (Optional — for ITSM-native organizations)                 │
│                                                                         │
│  Monitors PCE draft changes → classifies risk → routes to approvers    │
│  Slack ·· ServiceNow ·· Jira ·· Webhooks ·· GitHub Issues             │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component 1 — Policy GitOps

Git is the source of truth. A plugger daemon exports PCE policy to structured YAML on a schedule. Engineers edit YAML, open pull requests, and the pipeline validates every change before it can merge. On merge, the same pipeline provisions the diff back to PCE.

**Best for:** Git-native engineering organizations, teams already using GitHub for code review.

### Component 2 — Policy Workflow

A change detection daemon monitors PCE draft policy, classifies every change by risk level, and routes approval requests to external systems (Slack, ServiceNow, Jira, webhooks). Engineers continue working in the PCE GUI; the plugin adds the governance layer on top.

**Best for:** ITSM-native organizations, teams where the PCE is the primary UI, ServiceNow shops.

**You can use either independently, or both together for defense in depth.**

---

## Reference Architecture: Policy GitOps

The GitOps component provides a complete reference architecture. Deploy it as-is or adapt it to your organization.

### Repository Layout

```
illumio-policy/                         ← your policy repository
├── CODEOWNERS                          ← GitHub team enforcement
├── README.md                           ← team runbook
├── .github/
│   └── workflows/
│       ├── validate-policy.yml         ← runs on every PR
│       └── provision-policy.yml        ← runs on merge to main
├── .illumio/
│   ├── config.yaml                     ← PCE connection + behavior
│   ├── security-rules.yaml             ← configurable security checks
│   └── traffic-evidence.yaml           ← query settings
├── scopes/
│   ├── _global/                        ← unscoped: DNS, NTP, core services
│   ├── app-payments_env-prod/
│   │   ├── _scope.yaml                 ← label definitions + owner team
│   │   ├── intra-rules.yaml            ← within-scope rules
│   │   └── cross-scope/
│   │       └── to-shareddb.yaml        ← rules reaching outside this scope
│   └── app-shareddb_env-prod/
│       ├── _scope.yaml
│       ├── intra-rules.yaml
│       └── inbound/
│           └── from-payments.yaml      ← mirror of payments' cross-scope rule
├── ip-lists/
│   ├── any.yaml
│   ├── rfc1918.yaml
│   └── zscaler-exit-ips.yaml
└── services/
    ├── https.yaml
    ├── postgresql.yaml
    └── custom-app.yaml
```

### Scope Model

Policy is organized around **scopes** — pairs of labels (typically `app` + `env`) that define a team's blast radius.

| Rule Type | Location | Who Must Approve |
|---|---|---|
| **Intra-scope** | `scopes/{scope}/intra-rules.yaml` | Scope owner team |
| **Cross-scope** (requester side) | `scopes/{scope}/cross-scope/to-{target}.yaml` | Requester team + target team + security |
| **Cross-scope** (target side) | `scopes/{scope}/inbound/from-{requester}.yaml` | Same as above |
| **Global** (unscoped) | `scopes/_global/` | Security team only |

This structure makes it impossible for Team A to add a rule into Team B's scope without Team B's explicit GitHub review and approval.

### The Pull Request Workflow

```
1. Engineer creates branch, edits YAML
2. Opens pull request
3. GitHub Actions pipeline runs automatically:
   ├── YAML syntax validation
   ├── Security policy checks (8 configurable rules)
   ├── Traffic evidence query (PCE Explorer API)
   ├── Policy resolution (which workloads are affected)
   ├── Firewall change request generation
   └── PR comment posted with full findings
4. CODEOWNERS enforces required reviewers:
   ├── Scope owner (payments-team)
   ├── Target scope owner (database-team, for cross-scope)
   └── Security team (for cross-scope and global)
5. All checks pass + all reviewers approve → merge unblocked
6. Merge to main → provision-policy.yml runs → PCE draft updated
7. Full audit trail: Git diff + PR + reviews + merge timestamp
```

---

## Validation Pipeline

Every pull request triggers a five-stage pipeline. All stages run against the changed files only — the full repository is never re-validated unnecessarily.

### Stage 1 — YAML Lint

Every changed `.yaml` file is parsed. Deleted files are skipped gracefully. Invalid syntax blocks the PR immediately before any API calls are made.

### Stage 2 — Security Checks

Eight configurable rules evaluated against the policy diff:

| Rule | Severity | What It Catches |
|---|---|---|
| **SEC-001** | 🚫 Critical | Any-to-any rules (`ams → ams` in global scope) |
| **SEC-002** | 🚫 Critical | Port ranges wider than 1,000 ports (e.g. 1–65535) |
| **SEC-003** | 🚫 Critical | Insecure protocols — FTP/21, Telnet/23, TFTP/69, rlogin/513, rsh/514 |
| **SEC-004** | ⚠️ High | Cross-scope rules missing a `justification` field |
| **SEC-005** | ⚠️ High | RDP (3389) or SMB (445) — lateral movement vectors |
| **SEC-006** | ⚠️ High | Database ports (5432, 3306, 1433, 1521, 27017) exposed to non-role consumers |
| **SEC-007** | ⚠️ Medium | IP lists with /8 or broader CIDR (e.g. 10.0.0.0/8 = 16 million IPs) |
| **SEC-008** | ⚠️ High | All Workloads or Any IP as consumer without a role-specific provider |

Rules are **fully configurable** in `.illumio/security-rules.yaml`. Each rule supports exemptions — for example, exempting a core-services scope from SEC-005 when SMB is legitimately required for Active Directory.

Critical findings (SEC-001, 002, 003) **block the PR**. High and medium findings post warnings but do not block by default (configurable).

### Stage 3 — Traffic Evidence

When a rule is added or modified, the pipeline queries the PCE's Explorer API for actual blocked traffic matching that rule's pattern over the past 30 days (configurable).

**What this answers:** *Is this rule justified by real traffic, or is it unnecessary policy sprawl?*

| Verdict | Meaning |
|---|---|
| ✅ **Justified** | 10+ blocked connections found in the lookback window |
| ⚠️ **Weak evidence** | 1–9 blocked connections — reviewers should verify |
| 🔘 **No evidence** | Zero matching flows — rule may be premature or unnecessary |

For **rule deletions**, the logic inverts: the pipeline queries for *allowed* connections that would be blocked by removing the rule. If 4,500 active connections depend on a rule you're about to delete, reviewers see that before approving.

Traffic evidence is never a blocker — it's decision support for reviewers.

### Stage 4 — Policy Resolution

The pipeline resolves labels to actual workloads using the PCE API, so reviewers see concrete impact:

```
consumers:
  - label: {role: processing}       ← 3 workloads: pay-proc-01, pay-proc-02, pay-proc-03

providers:
  - label: {role: db}               ← 2 workloads: shareddb-primary, shareddb-replica
```

### Stage 5 — Firewall Change Request

A structured firewall change request is generated and committed to the PR branch under `fw-changes/`, mirroring the source file structure. Each changed scope gets its own CSV and JSON file:

```
fw-changes/
└── scopes/
    └── app-payments_env-prod/
        ├── intra-rules.csv
        └── intra-rules.json
```

This provides a machine-readable artifact for downstream ITSM or CMDB integration.

---

## PR Comment

Every pull request receives a single auto-updating comment with the full validation report.

```
## Policy Change Report

![Status](https://img.shields.io/badge/Status-APPROVED-brightgreen?style=flat-square)
![Rules](https://img.shields.io/badge/Rules-+3_added-blue?style=flat-square)
![Security](https://img.shields.io/badge/Security-1_warning-yellow?style=flat-square)
![Traffic](https://img.shields.io/badge/Traffic-2_of_3_justified-green?style=flat-square)

### Changed Files

| File | Added | Modified | Deleted |
|------|-------|----------|---------|
| scopes/app-payments_env-prod/intra-rules.yaml | 2 | 0 | 0 |
| scopes/app-shareddb_env-prod/inbound/from-payments.yaml | 1 | 0 | 0 |

### Security Analysis

| Rule | Status | Finding |
|------|--------|---------|
| SEC-001 Any-to-any | ✅ Pass | — |
| SEC-002 Port range | ✅ Pass | — |
| SEC-005 RDP/SMB | ⚠️ Warn | 3389/tcp in cross-scope rule — potentially blocks this PR |
| SEC-006 Database ports | ✅ Pass | — |

### Traffic Evidence

| Rule | Ports | Evidence | Connections | Sources | Verdict |
|------|-------|----------|-------------|---------|---------|
| web-to-processing | 8443/tcp | ✅ Found | 4,523 blocked | 3 unique | JUSTIFIED |
| processing-to-shareddb | 5432/tcp | ✅ Found | 891 blocked | 3 unique | JUSTIFIED |
| deny-db-to-web | 8443/tcp | 🔘 None | 0 | — | NO EVIDENCE |

### Rule Deleted: legacy-web-access

🔴 **4,521 active connections** — removing blocks them (3 sources)

Reviewers should verify this connection is intentionally being removed.
```

The comment is **updated in place** on every push — the PR thread stays clean.

---

## CODEOWNERS Enforcement

Branch protection + CODEOWNERS is the enforcement mechanism. No merge is possible without the required approvals.

```
# .github/CODEOWNERS

# Security team reviews all global, cross-scope, and infrastructure changes
scopes/_global/           @org/security-team
scopes/*/cross-scope/     @org/security-team
scopes/*/inbound/         @org/security-team
ip-lists/                 @org/security-team
services/                 @org/security-team
.illumio/                 @org/security-team

# Each application team owns their scope
scopes/app-payments_env-prod/    @org/payments-team
scopes/app-shareddb_env-prod/    @org/database-team
scopes/app-ordering_env-prod/    @org/ordering-team
```

**Cross-scope rule example:** Payments engineer adds a rule from payments to shareddb.

1. PR touches `cross-scope/to-shareddb.yaml` and `inbound/from-payments.yaml`
2. CODEOWNERS matches trigger required reviews from:
   - `@org/payments-team` (requester — author auto-approves)
   - `@org/database-team` (target — must explicitly approve)
   - `@org/security-team` (cross-scope pattern — must explicitly approve)
3. PR comment shows 891 blocked flows justifying the rule
4. Database team reviews the evidence, approves
5. Security team validates least-privilege, approves
6. GitHub unblocks merge → plugin provisions to PCE
7. Git records: author, reviewers, merge timestamp, exact diff

---

## YAML Format Reference

### Scope Definition

```yaml
# scopes/app-payments_env-prod/_scope.yaml
name: payments-prod
labels:
  app: payments
  env: prod
owners:
  - team: payments-team
    github: "@org/payments-team"
description: "Payment processing — production"
```

### Ruleset

```yaml
# scopes/app-payments_env-prod/intra-rules.yaml
name: payments-prod-intra
enabled: true

scopes:
  - - label: {app: payments}
    - label: {env: prod}

rules:
  - name: web-to-processing
    enabled: true
    consumers:
      - label: {role: web}
    providers:
      - label: {role: processing}
    services:
      - {port: 8443, proto: tcp}

  - name: processing-to-db
    enabled: true
    consumers:
      - label: {role: processing}
    providers:
      - label: {role: db}
    services:
      - {port: 5432, proto: tcp}

deny_rules:
  - name: deny-db-to-web
    type: deny
    enabled: true
    consumers:
      - label: {role: db}
    providers:
      - label: {role: web}
    services:
      - {port: 8443, proto: tcp}
```

### Cross-Scope Rule

```yaml
# scopes/app-payments_env-prod/cross-scope/to-shareddb.yaml
name: payments-to-shareddb
type: extra-scope

requester:
  scope: payments-prod
  consumers:
    - label: {role: processing}

target:
  scope: shareddb-prod
  providers:
    - label: {role: db}

services:
  - {port: 5432, proto: tcp}

justification: "Payment processing requires direct DB write access for transaction commits"
requested_by: alice@example.com
requested_date: "2026-04-26"
```

### Actor Formats

```yaml
consumers:
  - label: {role: web}              # Label reference (most common)
  - actors: ams                     # All managed workloads
  - ip_list: {name: "Zscaler Exit IPs"}  # IP list by name
  - workload: {href: "/orgs/1/workloads/abc123"}  # Specific workload
```

### IP List

```yaml
name: RFC1918
description: "Private IPv4 address ranges"
ip_ranges:
  - from_ip: "10.0.0.0/8"
  - from_ip: "172.16.0.0/12"
  - from_ip: "192.168.0.0/16"
```

### Service

```yaml
name: PostgreSQL
service_ports:
  - port: 5432
    proto: tcp
```

---

## Audit Trail

Every change produces a complete, immutable audit record in Git:

| Question | Answer |
|---|---|
| **Who requested it?** | Git author of the PR |
| **Who reviewed it?** | GitHub PR reviewers + approval timestamps |
| **What exactly changed?** | Git diff — line-by-line |
| **When was it approved?** | PR merge timestamp |
| **Why was it needed?** | PR description + traffic evidence in PR comment |
| **Was it necessary?** | Traffic evidence column in PR comment |
| **What was the risk?** | Security findings in PR comment |
| **What systems are affected?** | Policy resolution (workload list) in PR comment |

For compliance teams (SOC 2, PCI-DSS, HIPAA, SOX): the PR thread is the change authorization record. `git blame` and `git log` on any policy file show the full history of who changed what and when.

---

## Component 2 — Policy Workflow

For organizations where engineers use the PCE GUI directly, the Policy Workflow plugin adds a governance layer without changing the UI.

### How It Works

1. Plugin polls PCE every 5 minutes, comparing draft vs active policy
2. Every detected change is classified by risk level
3. Approval request routed to the appropriate team via configured adapter
4. Approver approves or rejects
5. On approval, plugin provisions the change to PCE active policy
6. Full change record stored for audit

### Risk Classification

| Level | Triggers | Routing |
|---|---|---|
| 🔴 **Critical** | Any-to-any rules, port range > 1,000, enforcement boundary deletion | Security leadership only |
| 🟠 **High** | Cross-scope rules, risky ports (RDP/SMB/RPC/VNC), broad CIDRs (/0–/8) | Scope owner + security team |
| 🟡 **Medium** | New intra-scope rules, modified rules, IP list changes | Scope owner |
| 🟢 **Low** | Rule disabled, rule deleted, metadata change | Auto-approved |
| ℹ️ **Info** | Label group or service definition changes | Auto-approved, logged |

### Approval Adapters

| Adapter | What Happens |
|---|---|
| **Slack** | Block Kit message with risk summary and Approve/Reject buttons |
| **ServiceNow** | Change Request created with risk level and assignment group; polled for approval |
| **Jira** | Issue created with priority mapped to risk level |
| **GitHub Issues** | Issue created with risk labels |
| **Webhook** | JSON POST to any URL; approval via HTTP callback |

### Multi-Team Approval

Scope routing in `approval-config.yaml`:

```yaml
approvers:
  scopes:
    "app=payments AND env=prod":
      team: payments-team
      slack_channel: "#payments-approvals"
      servicenow_group: "Payments Engineering"

    "app=shareddb AND env=prod":
      team: database-team
      slack_channel: "#dba-approvals"

  cross_scope:
    team: security-team
    slack_channel: "#security-approvals"

  critical:
    team: security-leadership
    slack_channel: "#security-urgent"
```

With `REQUIRE_ALL_APPROVERS=true` (default), all required teams must approve. A single rejection from any team rejects the change immediately.

### Change Lifecycle

```
DETECTED → PENDING → APPROVED → PROVISIONING → PROVISIONED
               ↘ REJECTED (any team vetoes)
               ↘ EXPIRED  (timeout, default 7 days)
```

### Dashboard

A built-in web dashboard (port 8080) shows all pending approvals sorted by risk level, recent activity, and approval configuration. Approve, reject, or manually trigger provisioning from the UI.

### Drift Detection

The workflow plugin detects out-of-band changes — engineers making changes directly in the PCE GUI — and routes them through the same approval process as any other change. Nothing bypasses the governance layer.

---

## Plugin Configuration

### Policy GitOps Plugin (Environment Variables)

| Variable | Default | Description |
|---|---|---|
| `PCE_HOST` | required | PCE URL |
| `PCE_PORT` | `8443` | PCE API port |
| `PCE_ORG_ID` | `1` | Organization ID |
| `PCE_API_KEY` | required | API key username |
| `PCE_API_SECRET` | required | API key secret |
| `GIT_REPO_URL` | required | Policy repository URL |
| `GIT_TOKEN` | required | GitHub personal access token |
| `GIT_BRANCH` | `main` | Target branch |
| `SYNC_MODE` | `export` | `export` \| `provision` \| `bidirectional` |
| `SCAN_INTERVAL` | `3600` | Seconds between sync cycles |
| `EXPORT_AS_PR` | `false` | Create PRs instead of direct commits |
| `AUTO_PROVISION` | `false` | Auto-promote draft to active on provision |
| `DRIFT_ALERT` | `true` | Detect and flag out-of-band PCE GUI changes |

### Sync Modes

| Mode | Direction | When to Use |
|---|---|---|
| `export` | PCE → Git | Initial bootstrap; PCE is still being edited directly |
| `provision` | Git → PCE | Git is source of truth; PCE receives from Git only |
| `bidirectional` | Both | Transition period only — avoid long-term (sync loops) |

---

## Getting Started

### Prerequisites

- Illumio PCE (on-prem or SaaS) with API credentials
- GitHub organization with a new policy repository
- Docker (to run the plugin container)

### Quickstart

```bash
# 1. Create your policy repository from the template
gh repo create my-org/illumio-policy --template alexgoller/illumio-policy-gitops/template

# 2. Configure PCE connection
# Edit .illumio/config.yaml with your PCE host and org ID

# 3. Add GitHub Actions secrets
gh secret set PCE_HOST      --body "https://pce.example.com"
gh secret set PCE_PORT      --body "8443"
gh secret set PCE_ORG_ID    --body "1"
gh secret set PCE_API_KEY   --body "<your-api-key>"
gh secret set PCE_API_SECRET --body "<your-api-secret>"

# 4. Enable branch protection
# Require PR, status checks (Policy Validation), and CODEOWNERS review

# 5. Run the plugin to bootstrap policy from PCE to Git
docker run --rm \
  -e PCE_HOST=https://pce.example.com \
  -e PCE_API_KEY=... \
  -e PCE_API_SECRET=... \
  -e GIT_REPO_URL=https://github.com/my-org/illumio-policy \
  -e GIT_TOKEN=... \
  -e SYNC_MODE=export \
  ghcr.io/alexgoller/illumio-policy-gitops:latest

# 6. Update CODEOWNERS with your real GitHub teams
# 7. Create a test PR to verify the validation pipeline runs
# 8. Switch SYNC_MODE to 'provision' — Git is now the source of truth
```

### GitHub Actions Secrets Reference

| Secret | Description |
|---|---|
| `PCE_HOST` | PCE URL including scheme (e.g. `https://pce.example.com`) |
| `PCE_PORT` | PCE API port (typically `8443`) |
| `PCE_ORG_ID` | PCE organization ID (typically `1`) |
| `PCE_API_KEY` | API key username from PCE |
| `PCE_API_SECRET` | API key secret from PCE |

---

## Repository Structure (This Repo)

```
plugin/          Export/provision plugin — runs as a plugger daemon
workflow/        Approval workflow plugin — ITSM bridge
action/scripts/  Pipeline scripts (validate, provision, evidence, report)
template/        Starter policy repository (copy this to get started)
```

---

## Roadmap

- [ ] GitLab MR and Bitbucket PR support
- [ ] Terraform bridge (export policy as HCL)
- [ ] Policy simulation ("what-if" preview against PCE draft)
- [ ] Auto-remediation PRs (drift detected → auto-create reconciliation PR)
- [ ] Label management in Git (same GitOps workflow)
- [ ] Time-boxed approvals (approved for 48h, then auto-revoke)
- [ ] Multi-PCE support (single approval flow across prod/DR/dev)
- [ ] Reusable GitHub Action for zero-copy adoption

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for versioning rules, release process, and PR conventions.

## License

MIT — see [LICENSE](LICENSE).
