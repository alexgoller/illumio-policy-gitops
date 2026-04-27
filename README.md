# Illumio Policy GitOps

Policy-as-code and approval workflow for Illumio PCE segmentation policy. Two components:

1. **Policy GitOps** (`plugin/`) — Export policy to Git as structured YAML, enforce multi-team review via PRs with CODEOWNERS, security checks, traffic evidence, and auto-provisioning on merge.

2. **Policy Workflow** (`workflow/`) — Approval bridge for policy changes. Detects draft changes, classifies risk, routes to Slack/ServiceNow/webhooks for approval, provisions on approval.

Both work independently or together. Use GitOps for Git-native teams, Workflow for ITSM-native teams, or both for defense in depth.

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [How This Relates to PCE Versioning](#how-this-relates-to-pce-versioning)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Scope Concepts](#scope-concepts)
- [Repository Structure](#repository-structure)
- [YAML Format Reference](#yaml-format-reference)
- [CODEOWNERS and Multi-Team Workflow](#codeowners-and-multi-team-workflow)
- [Security Pipeline](#security-pipeline)
- [Traffic Evidence Pipeline](#traffic-evidence-pipeline)
- [PR Comment Visualization](#pr-comment-visualization)
- [GitHub Actions Workflows](#github-actions-workflows)
- [Plugin Configuration](#plugin-configuration)
- [Sync Modes](#sync-modes)
- [Getting Started](#getting-started)
- [Standalone Project Roadmap](#standalone-project-roadmap)

---

## Problem Statement

Illumio PCE has built-in policy versioning through its draft/active model, and its event log records who provisioned what. For single-team environments where one group owns all policy, PCE's native capabilities are often sufficient.

The gap appears at scale. When multiple teams own different application scopes, PCE's RBAC controls who can edit, but provides no cross-team review gate. Team A can create extra-scope rules that touch Team B's applications without Team B ever approving — or even knowing. There is no peer review step between draft and active. Auditors asking for evidence of change review processes find PCE events, but not the review thread where a second engineer signed off. And organizations running multiple PCEs (prod, DR, dev, regional) have no single source of truth for keeping policy consistent across environments.

Cross-scope rules require out-of-band coordination -- Slack messages, email threads, tickets that nobody can find six months later.

**Who feels this pain:**

- **Security architects** who want policy-as-code discipline and least-privilege enforcement
- **Compliance teams** who need evidence of change review processes for audits (SOC2, PCI-DSS, HIPAA)
- **Multi-team environments** where Team A should not unilaterally create rules touching Team B's application scope
- **Operations teams** who want rollback capability when a policy change breaks something -- `git revert` is faster than manually undoing PCE changes

**What this project provides:**

- Git repository as the source of truth for segmentation policy
- YAML files organized by scope ownership, so each team owns their directory
- Pull request workflow with automated security checks, traffic evidence, and CODEOWNERS-enforced reviews
- Drift detection between Git and PCE to catch out-of-band GUI changes
- Automated provisioning on merge -- approved policy goes live without manual intervention

---

## How This Relates to PCE Versioning

Illumio PCE has its own versioning model: the draft/active policy separation records every provisioning event with a timestamp and the user who triggered it. This is solid, mature versioning. This project does not replace it.

What this project adds is a **review layer** between authoring and provisioning:

| Capability | PCE native | This project |
|---|---|---|
| Policy versioning | Yes (draft/active history) | Additive (Git history + PR reviews) |
| Who changed what | Yes (PCE event log) | Additive (Git blame, PR audit trail) |
| Peer review gate | No | Yes (GitHub PRs + required approvals) |
| Cross-team approval | No | Yes (CODEOWNERS enforces ownership) |
| External audit trail | No (requires PCE access) | Yes (Git log is self-contained) |
| CI/CD validation | No | Yes (security checks, traffic evidence) |
| Multi-PCE consistency | No | Yes (Git is the single source of truth) |
| IaC integration | No | Yes (YAML in Git alongside Terraform etc.) |

**When to use this project:**

- Multiple teams own different application scopes and need enforced cross-team review
- Compliance frameworks (SOC 2, PCI-DSS, HIPAA) require evidence of peer review on policy changes
- Policy should live in Git alongside infrastructure-as-code (Terraform, Ansible, Helm)
- Multiple PCE environments (prod, DR, dev, regional) need a single source of truth
- Out-of-band GUI changes are a recurring problem and drift detection is wanted

**When PCE native is sufficient:**

- Single team owns all policy and internal review processes are informal
- PCE event logs satisfy audit requirements without external evidence
- No requirement for policy-as-code discipline or IaC integration

**The sync model:**

PCE remains the enforcement engine and the runtime source of truth. Git adds the review and CI layer. The plugin provisions to PCE draft (preserving PCE's own draft/active workflow), so nothing bypasses PCE versioning -- it extends it with an upstream approval gate.

```
Author edits YAML → opens PR → CI validates → team approves
       → merge → plugin provisions to PCE draft → PCE draft → active
```

---

## How It Works

1. **Export**: The plugin reads all rulesets, IP lists, and services from the PCE and writes them as YAML files into a Git repository, organized by scope (application + environment labels)
2. **Edit**: Engineers create branches, edit or add YAML files in their team's scope directory, and open pull requests
3. **Validate**: GitHub Actions runs on every PR -- YAML lint, security rule evaluation, traffic evidence queries against the PCE, and renders a comprehensive PR comment
4. **Review**: CODEOWNERS ensures the right teams review changes. Cross-scope rules automatically require approval from the target team and the security team
5. **Provision**: On merge to main, a second GitHub Actions workflow provisions the changed policy to the PCE as draft (or active, configurable)
6. **Drift Detect**: The plugin periodically compares Git state against PCE active policy and flags any differences

---

## Architecture

```
                         +---------------------+
                         |                     |
                         |    Illumio PCE       |
                         |                     |
                         |  Active Policy      |
                         |  Draft Policy       |
                         |  Traffic Flows      |<--- evidence for rule requests
                         |                     |
                         +----+-----+-----+----+
                              |     |     |
           export (PCE->Git)  |     |     |  provision (Git->PCE)
           drift detection    |     |     |  traffic evidence queries
                              |     |     |
                    +---------+     |     +----------+
                    |               |                |
          +---------v--------+     |     +----------v---------+
          |                  |     |     |                    |
          | policy-gitops    |     |     | GitHub Actions     |
          | plugin           |     |     | (in policy repo)   |
          |                  |     |     |                    |
          | - Export PCE->Git|     |     | On PR:             |
          | - Drift detect   |     |     |   - YAML lint      |
          | - Import Git->PCE|     |     |   - Security check |
          | - Dashboard UI   |     |     |   - Traffic query  |
          |                  |     |     |   - PR comment     |
          | (runs in plugger |     |     |                    |
          |  container)      |     |     | On merge:          |
          |                  |     |     |   - Provision      |
          +---------+--------+     |     +----------+---------+
                    |              |                 |
                    |              |                 |
                    +------+-------+---------+------+
                           |                 |
                    +------v-----------------v------+
                    |                               |
                    |  Git Repository               |
                    |  (illumio-policy)              |
                    |                               |
                    |  scopes/                      |
                    |    app-payments_env-prod/      |
                    |    app-shareddb_env-prod/      |
                    |  ip-lists/                    |
                    |  services/                    |
                    |  CODEOWNERS                   |
                    |  .github/workflows/           |
                    |                               |
                    +-------------------------------+
```

There are two distinct components:

1. **The plugger plugin** (`policy-gitops/main.py`) -- a long-running daemon that handles PCE-to-Git export, Git-to-PCE provisioning, and drift detection. It runs inside a plugger container alongside the PCE and serves a web dashboard on port 8080.

2. **The GitHub Actions pipeline** (lives inside the customer's policy repository) -- handles PR validation, security checks, traffic evidence collection, PR comment rendering, and provisioning on merge. The pipeline scripts (`security-check.py`, `traffic-evidence.py`) are included in the `action/scripts/` directory and are copied into the customer's repo.

---

## Scope Concepts

Scopes are the fundamental organizational unit. A scope is a set of Illumio labels (typically `app` + `env`) that defines the boundary around a team's application workloads. Every ruleset in the PCE is scoped, and the Git repository mirrors this structure as directories.

### Intra-Scope Rules

Rules where both consumers and providers are within the same scope. These are the most common rules -- for example, allowing the `web` role to talk to the `app` role on port 8443, all within the `app=payments, env=prod` scope.

Intra-scope rules live directly in the scope directory:

```
scopes/app-payments_env-prod/intra-rules.yaml
```

Only the owning team (`@org/payments-team`) needs to approve changes to these rules.

### Extra-Scope Rules (Cross-Scope)

Rules where consumers are outside the scope boundary (`unscoped_consumers: true`). These allow workloads from other applications to reach into a scope. For example, the `payments` app needs to talk to the `shareddb` app on port 5432.

Extra-scope rules are stored in a `cross-scope/` subdirectory of the requester's scope and an `inbound/` subdirectory of the target scope:

```
scopes/app-payments_env-prod/cross-scope/to-shareddb.yaml    (requester side)
scopes/app-shareddb_env-prod/inbound/from-payments.yaml      (target side, mirror)
```

Both teams must approve via CODEOWNERS, plus the security team reviews all cross-scope rules.

### Multi-Scope Rulesets

Some rulesets span multiple scopes (e.g., a "coreservices" ruleset that applies globally). These live in `scopes/_global/`:

```
scopes/_global/coreservices.yaml
```

Global rulesets require security team approval.

### How Scopes Map to Directories

The plugin builds directory names from a ruleset's scope labels. A ruleset scoped to `app=payments, env=prod` maps to the directory `scopes/app-payments_env-prod/`. The mapping logic:

1. Read the first scope entry's labels from the ruleset
2. For each label, format as `key-value` (e.g., `app-payments`, `env-prod`)
3. Join the pairs with underscores: `app-payments_env-prod`
4. If no scope labels exist, map to `scopes/_global/`

This format is self-documenting — the directory name tells you both the label key and value without opening `_scope.yaml`. It also avoids ambiguity when different label keys share the same value (e.g., `loc=prod` vs `env=prod`).

Each scope directory contains a `_scope.yaml` file that defines the scope's labels and team ownership. This file is auto-generated during export and can be manually edited to assign owners.

### How Scopes Affect Traffic Evidence Queries

When the traffic evidence pipeline analyzes a rule, the query strategy depends on scope type:

- **Intra-scope rules**: Both source and destination are constrained to the scope's labels. The PCE query filters on consumer labels AND provider labels.
- **Extra-scope rules**: The destination (provider) is constrained to the target scope. The source (consumer) may be unscoped or scoped to the requester's scope.
- **Multi-scope rules**: One query is issued per scope, with results aggregated.

---

## Repository Structure

This is the structure of the **customer's policy repository** (the Git repo that stores the policy YAML). The template is provided in `template/`.

```
illumio-policy/                          <- The customer's policy repo
|
+-- README.md                            <- How-to for the team (template provided)
+-- CODEOWNERS                           <- GitHub/GitLab code ownership rules
|
+-- .github/
|   +-- workflows/
|   |   +-- validate-policy.yml          <- Runs on PR: lint, security check, traffic evidence
|   |   +-- provision-policy.yml         <- Runs on merge to main: provision to PCE
|   +-- scripts/
|       +-- security-check.py            <- Security rule evaluator
|       +-- traffic-evidence.py          <- PCE traffic query engine
|
+-- .illumio/
|   +-- config.yaml                      <- PCE connection settings + repo behavior
|   +-- security-rules.yaml              <- Configurable security check rules
|   +-- team-config.yaml                 <- Scope-to-team ownership mapping
|
+-- scopes/
|   +-- _global/                         <- Unscoped / global rulesets
|   |   +-- default.yaml                 <- Default rules (e.g., DNS, NTP)
|   |   +-- coreservices.yaml            <- Core infrastructure rules (AD, SCCM)
|   |
|   +-- app-payments_env-prod/            <- Team A's application scope (app=payments, env=prod)
|   |   +-- _scope.yaml                  <- Scope definition (labels, owners)
|   |   +-- intra-rules.yaml             <- Intra-scope rules (web->app->db)
|   |   +-- cross-scope/
|   |       +-- to-shareddb.yaml         <- Cross-scope rule request (outbound)
|   |
|   +-- app-shareddb_env-prod/           <- Team B's application scope (app=shareddb, env=prod)
|   |   +-- _scope.yaml
|   |   +-- intra-rules.yaml
|   |   +-- inbound/
|   |       +-- from-payments.yaml       <- Approved inbound cross-scope rule
|   |
|   +-- app-ordering_env-prod/           <- Team C's application scope (app=ordering, env=prod)
|       +-- _scope.yaml
|       +-- intra-rules.yaml
|
+-- ip-lists/                            <- Shared IP list definitions
|   +-- any.yaml                         <- "Any" (0.0.0.0/0)
|   +-- rfc1918.yaml                     <- RFC1918 private ranges
|   +-- zscaler-ips.yaml                 <- Vendor/partner IP ranges
|
+-- services/                            <- Service definitions (port/protocol)
|   +-- https.yaml
|   +-- postgresql.yaml
|   +-- custom-app-8443.yaml
|
+-- labels/
    +-- labels.yaml                      <- Label definitions (usually not managed here)
```

### Plugin project structure (this repository)

```
policy-gitops/
+-- main.py                              <- Plugin entrypoint: daemon, dashboard, sync engine
+-- requirements.txt                     <- Python dependencies
+-- Dockerfile                           <- Container image (Python 3.12 + git)
+-- plugin.yaml                          <- Plugger install manifest
+-- .plugger/metadata.yaml               <- Plugger container discovery metadata
+-- DESIGN.md                            <- Original design document
+-- README.md                            <- This file
|
+-- action/
|   +-- scripts/
|       +-- security-check.py            <- Security rule evaluator for GitHub Actions
|       +-- traffic-evidence.py          <- Traffic evidence collector for GitHub Actions
|
+-- template/                            <- Starter template for the customer's policy repo
    +-- .github/workflows/
    |   +-- validate-policy.yml
    |   +-- provision-policy.yml
    +-- .illumio/
    |   +-- config.yaml
    |   +-- security-rules.yaml
    +-- CODEOWNERS
    +-- README.md
```

---

## YAML Format Reference

All policy objects are stored as YAML files. The format is designed to be human-readable and diffable, using label key:value pairs instead of PCE HREFs.

### Scope Definition (`_scope.yaml`)

Every scope directory contains a `_scope.yaml` file that defines the scope's identity, label constraints, and team ownership.

```yaml
# scopes/payments-prod/_scope.yaml
name: payments-prod
labels:
  app: payments
  env: prod
owners:
  - team: payments-team
    github: @org/payments-team
description: "Payment processing application -- production environment"
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Human-readable scope name (matches directory name) |
| `labels` | map | yes | Illumio label key:value pairs that define this scope |
| `owners` | list | no | Teams that own this scope (used for CODEOWNERS generation) |
| `owners[].team` | string | no | Team identifier |
| `owners[].github` | string | no | GitHub team handle (e.g., `@org/team-name`) |
| `description` | string | no | Human-readable description of the scope |

### Intra-Scope Ruleset YAML

Standard rulesets containing allow rules within a single scope. This is the most common file type.

```yaml
# scopes/payments-prod/intra-rules.yaml
name: payments-prod-intra
description: "Intra-scope rules for payments production"
enabled: true

scopes:
  - - label: {app: payments}
    - label: {env: prod}

rules:
  - name: web-to-app
    enabled: true
    consumers:
      - label: {role: web}
    providers:
      - label: {role: processing}
    services:
      - {port: 8443, proto: tcp}
      - {port: 8080, proto: tcp}

  - name: app-to-db
    enabled: true
    consumers:
      - label: {role: processing}
    providers:
      - label: {role: db}
    services:
      - {port: 5432, proto: tcp}

  - name: web-to-cache
    enabled: true
    consumers:
      - label: {role: web}
    providers:
      - label: {role: cache}
    services:
      - {port: 6379, proto: tcp}

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
      - {port: 8080, proto: tcp}
```

**Top-level fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Ruleset name (unique across the PCE) |
| `description` | string | no | Human-readable description |
| `enabled` | bool | no | Whether the ruleset is active (default: `true`) |
| `scopes` | list[list] | no | Scope label constraints; inferred from `_scope.yaml` if omitted |
| `rules` | list | yes | List of allow rules |
| `deny_rules` | list | no | List of deny rules (evaluated before allow rules) |

**Rule fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Rule name (stored as `description` in the PCE) |
| `enabled` | bool | no | Whether this rule is active (default: `true`) |
| `consumers` | list | yes | List of consumer actors (sources) |
| `providers` | list | yes | List of provider actors (destinations) |
| `services` | list | yes | List of services (ports/protocols) to allow |
| `unscoped_consumers` | bool | no | If `true`, consumers are not constrained to the ruleset scope |
| `sec_connect` | bool | no | Require SecureConnect (IPsec) for this rule |
| `machine_auth` | bool | no | Require machine authentication for this rule |

**Actor formats** (used in `consumers` and `providers`):

```yaml
# Label reference (most common)
- label: {role: web}
- label: {app: payments}

# All managed workloads
- actors: ams

# IP list reference (by name)
- ip_list: {name: "Zscaler Exit IPs"}

# Workload reference (by href, rarely used)
- workload: {href: "/orgs/1/workloads/abc123"}

# Label group reference
- label_group: {href: "/orgs/1/sec_policy/active/label_groups/xyz"}
```

**Service formats:**

```yaml
# Inline port/protocol (most common)
- {port: 443, proto: tcp}
- {port: 53, proto: udp}

# Port range
- {port: 8000, to_port: 8999, proto: tcp}

# Named service reference
- {name: PostgreSQL}

# ICMP
- {proto: icmp, icmp_type: 8, icmp_code: 0}
```

### Cross-Scope Rule YAML

Cross-scope (extra-scope) rules have a different format that explicitly identifies the requester scope, target scope, and includes a mandatory justification.

```yaml
# scopes/payments-prod/cross-scope/to-shareddb.yaml
name: payments-to-shareddb
description: "Payments app needs access to shared database"
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

justification: "Payment processing requires direct DB access for transaction writes"
requested_by: alice@example.com
requested_date: "2026-04-26"
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Rule name |
| `description` | string | no | Why this rule exists |
| `type` | string | yes | Must be `extra-scope` for cross-scope rules |
| `requester.scope` | string | yes | Name of the requesting scope |
| `requester.consumers` | list | yes | Consumer actors in the requester's scope |
| `target.scope` | string | yes | Name of the target scope |
| `target.providers` | list | yes | Provider actors in the target scope |
| `services` | list | yes | Services (ports/protocols) being requested |
| `justification` | string | yes | Why this cross-scope access is needed (SEC-004 enforces this) |
| `requested_by` | string | no | Email of the person requesting the rule |
| `requested_date` | string | no | Date the rule was requested |

### IP List YAML

```yaml
# ip-lists/rfc1918.yaml
name: RFC1918
description: "Private IPv4 address ranges per RFC 1918"
ip_ranges:
  - from_ip: "10.0.0.0/8"
    description: "Class A private"
  - from_ip: "172.16.0.0/12"
    description: "Class B private"
  - from_ip: "192.168.0.0/16"
    description: "Class C private"
```

```yaml
# ip-lists/zscaler-ips.yaml
name: Zscaler Exit IPs
description: "Zscaler cloud proxy egress IP addresses"
ip_ranges:
  - from_ip: "104.129.192.0/20"
  - from_ip: "165.225.0.0/17"
  - from_ip: "185.46.212.0/22"
fqdns:
  - "gateway.zscaler.net"
  - "mobile.zscaler.net"
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | IP list name (unique across the PCE) |
| `description` | string | no | What this IP list represents |
| `ip_ranges` | list | yes | List of IP range entries |
| `ip_ranges[].from_ip` | string | yes | IP address or CIDR (e.g., `10.0.0.0/8` or `192.168.1.5`) |
| `ip_ranges[].to_ip` | string | no | End of range (for non-CIDR ranges, e.g., `10.0.0.1` to `10.0.0.254`) |
| `ip_ranges[].exclusion` | bool | no | If `true`, this range is excluded from the IP list |
| `ip_ranges[].description` | string | no | Description of this range |
| `fqdns` | list | no | List of fully qualified domain names |

### Service YAML

```yaml
# services/postgresql.yaml
name: PostgreSQL
description: "PostgreSQL database server"
service_ports:
  - port: 5432
    proto: tcp
```

```yaml
# services/custom-app.yaml
name: Custom Web App
description: "Internal application with multiple ports"
service_ports:
  - port: 8080
    proto: tcp
  - port: 8443
    proto: tcp
  - port: 9090
    proto: tcp
```

```yaml
# services/windows-file-share.yaml
name: Windows File Share
description: "SMB/CIFS file sharing"
service_ports:
  - port: 445
    proto: tcp
  - port: 139
    proto: tcp
windows_services:
  - service_name: "LanmanServer"
    process_name: "svchost.exe"
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Service name (unique across the PCE) |
| `description` | string | no | What this service is |
| `service_ports` | list | yes | List of port/protocol definitions |
| `service_ports[].port` | int | yes | Port number |
| `service_ports[].to_port` | int | no | End of port range |
| `service_ports[].proto` | string | yes | Protocol: `tcp`, `udp`, `icmp`, or `icmpv6` |
| `service_ports[].icmp_type` | int | no | ICMP type (only for ICMP protocols) |
| `service_ports[].icmp_code` | int | no | ICMP code (only for ICMP protocols) |
| `windows_services` | list | no | Windows-specific service definitions |

---

## CODEOWNERS and Multi-Team Workflow

GitHub's CODEOWNERS file is the enforcement mechanism for multi-team review. When branch protection is configured with "Require review from Code Owners," GitHub will not allow a PR to merge until every team listed in CODEOWNERS for the changed files has approved.

### CODEOWNERS Layout

```
# Global policy -- security team must review all changes
scopes/_global/         @org/security-team
ip-lists/               @org/security-team
services/               @org/security-team
.illumio/               @org/security-team

# Per-scope ownership -- each team owns their application scope
scopes/app-payments_env-prod/   @org/payments-team
scopes/app-shareddb_env-prod/   @org/database-team
scopes/app-ordering_env-prod/   @org/ordering-team
scopes/app-frontend_env-prod/   @org/frontend-team

# Cross-scope rules always require security team review
scopes/*/cross-scope/   @org/security-team
scopes/*/inbound/       @org/security-team
```

### How It Enforces Review

**Scenario 1: Intra-scope change (simple)**

An engineer on the payments team adds a new rule to `scopes/app-payments_env-prod/intra-rules.yaml`. CODEOWNERS matches `scopes/app-payments_env-prod/` and requires `@org/payments-team` to review. Since the author is on that team, the PR can be approved by any teammate.

**Scenario 2: Cross-scope change (multi-team)**

An engineer creates a cross-scope rule from payments to shareddb. The PR contains two files:
- `scopes/app-payments_env-prod/cross-scope/to-shareddb.yaml` -- matches `scopes/app-payments_env-prod/` (payments team) AND `scopes/*/cross-scope/` (security team)
- `scopes/app-shareddb_env-prod/inbound/from-payments.yaml` -- matches `scopes/app-shareddb_env-prod/` (database team) AND `scopes/*/inbound/` (security team)

Three approvals are required:
1. `@org/payments-team` -- owns the requester scope
2. `@org/database-team` -- owns the target scope
3. `@org/security-team` -- reviews all cross-scope rules

### Step-by-Step Cross-Scope Flow

```
1. Team A (payments) creates a branch and adds two files:
   - scopes/app-payments_env-prod/cross-scope/to-shareddb.yaml
   - scopes/app-shareddb_env-prod/inbound/from-payments.yaml

2. Team A opens a PR against main

3. GitHub Actions validate-policy workflow runs:
   a. YAML lint: validates all YAML is parseable
   b. Security check: flags as HIGH severity (cross-scope, DB access)
   c. Traffic evidence: queries PCE for blocked flows on port 5432
      between payments consumers and shareddb providers
      -> Finds 891 blocked connections over 17 days -> JUSTIFIED
   d. Posts a comprehensive PR comment with all findings

4. CODEOWNERS triggers review requests:
   - @org/payments-team   -> auto-approved (author's team)
   - @org/database-team   -> MUST review (touches their inbound/ dir)
   - @org/security-team   -> MUST review (cross-scope/ and inbound/)

5. Database team reviews:
   - Sees the PR comment showing 891 blocked connections
   - "This is real traffic that we're blocking -- approve"

6. Security team reviews:
   - Validates least-privilege: specific port (5432), specific roles
   - No critical security findings
   - Approves

7. PR merges -> provision-policy workflow runs:
   - Reads changed YAML files
   - Creates the extra-scope ruleset on PCE draft
   - Optionally provisions draft -> active

8. Full audit trail remains in Git:
   - PR author = who requested the rule
   - PR reviewers = who approved it
   - Merge timestamp = when it was approved
   - Git diff = exactly what changed
   - PR comment = security analysis + traffic evidence
```

### CODEOWNERS Generation

The plugin can auto-generate the CODEOWNERS file from `_scope.yaml` definitions during export. The `ScopeMapper.build_codeowners()` method walks all scope directories, reads each `_scope.yaml` for the `owners` field, and generates the appropriate CODEOWNERS entries.

---

## Security Pipeline

The security pipeline evaluates every changed policy file against a configurable set of rules. Rules are defined in `.illumio/security-rules.yaml` in the policy repository. The pipeline is implemented in `action/scripts/security-check.py`.

### Security Rules Reference

#### SEC-001: No Any-to-Any Rules

| | |
|---|---|
| **Severity** | Critical |
| **Action** | Block (PR cannot merge) |
| **What it checks** | Whether both `providers` and `consumers` contain `{actors: ams}` (all managed workloads) |
| **Why it matters** | Any-to-any rules defeat the purpose of micro-segmentation. Every workload can talk to every other workload on the specified ports. |

**Example YAML that triggers SEC-001:**

```yaml
rules:
  - name: allow-everything
    consumers:
      - actors: ams          # <-- all managed workloads
    providers:
      - actors: ams          # <-- all managed workloads
    services:
      - {port: 443, proto: tcp}
```

#### SEC-002: No Broad Port Ranges

| | |
|---|---|
| **Severity** | Critical |
| **Action** | Block |
| **What it checks** | Whether any service has a port range (`to_port - port`) exceeding 1000 ports |
| **Why it matters** | Broad port ranges allow far more access than needed. A range of 1-65535 is effectively "all ports." |

**Example YAML that triggers SEC-002:**

```yaml
rules:
  - name: wide-open-ports
    consumers:
      - label: {role: web}
    providers:
      - label: {role: app}
    services:
      - {port: 1, to_port: 65535, proto: tcp}   # <-- 65534 port range
```

#### SEC-003: No Insecure Protocols

| | |
|---|---|
| **Severity** | Critical |
| **Action** | Block |
| **What it checks** | Whether any service uses ports 21 (FTP), 23 (Telnet), 69 (TFTP), 513 (rlogin), or 514 (rsh) |
| **Why it matters** | These protocols transmit credentials in cleartext. Use SSH (22) and SFTP instead. |

**Example YAML that triggers SEC-003:**

```yaml
rules:
  - name: allow-telnet
    consumers:
      - label: {role: jumpbox}
    providers:
      - label: {role: db}
    services:
      - {port: 23, proto: tcp}    # <-- Telnet
```

#### SEC-004: Cross-Scope Rules Need Justification

| | |
|---|---|
| **Severity** | High |
| **Action** | Warn (shown in PR comment, does not block) |
| **What it checks** | Whether files with `type: extra-scope` or `unscoped_consumers: true` have a `justification` field |
| **Why it matters** | Cross-scope rules break micro-segmentation boundaries. A justification creates an audit trail for why the access is needed. |

**Example YAML that triggers SEC-004:**

```yaml
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
# Missing: justification field    <-- triggers SEC-004
```

#### SEC-005: RDP/SMB Restricted

| | |
|---|---|
| **Severity** | High |
| **Action** | Warn |
| **What it checks** | Whether any service uses port 3389 (RDP) or 445 (SMB/CIFS) |
| **Why it matters** | RDP and SMB are the most common lateral movement vectors in enterprise breaches. Every rule using these ports should be explicitly justified. |

**Example YAML that triggers SEC-005:**

```yaml
rules:
  - name: allow-rdp
    consumers:
      - label: {role: jumpbox}
    providers:
      - label: {role: db}
    services:
      - {port: 3389, proto: tcp}    # <-- RDP
```

#### SEC-006: Database Ports Restricted to App Tier

| | |
|---|---|
| **Severity** | High |
| **Action** | Warn |
| **What it checks** | Whether services using database ports (5432, 3306, 1433, 1521, 27017) have consumers with a specific `role` label |
| **Why it matters** | Database ports should only be accessible from the application tier, not from all workloads. Without a role-specific consumer, any workload in scope can reach the database. |

**Example YAML that triggers SEC-006:**

```yaml
rules:
  - name: allow-db-from-anywhere
    consumers:
      - actors: ams              # <-- no specific role
    providers:
      - label: {role: db}
    services:
      - {port: 5432, proto: tcp}  # <-- PostgreSQL
```

#### SEC-007: IP List Broad CIDR

| | |
|---|---|
| **Severity** | Medium |
| **Action** | Warn |
| **What it checks** | Whether IP lists contain CIDR ranges with a prefix length of /8 or broader |
| **Why it matters** | A /8 CIDR covers 16 million IP addresses. IP lists this broad offer minimal security value. |

**Example YAML that triggers SEC-007:**

```yaml
# ip-lists/too-broad.yaml
name: Overly Broad
ip_ranges:
  - from_ip: "10.0.0.0/8"      # <-- /8 CIDR, 16M addresses
```

#### SEC-008: HTTP Without HTTPS

| | |
|---|---|
| **Severity** | Medium |
| **Action** | Warn |
| **What it checks** | Whether any service uses port 80 (HTTP) |
| **Why it matters** | HTTP transmits data in cleartext. Consider requiring HTTPS (port 443) instead. |

### Exemptions

Specific rulesets can be exempted from specific security rules. Exemptions are configured in `.illumio/security-rules.yaml`:

```yaml
exemptions:
  - ruleset_pattern: "coreservices"
    exempt_rules: [SEC-005]
    reason: "Active Directory requires SMB for domain operations"

  - ruleset_pattern: "legacy-monitoring"
    exempt_rules: [SEC-003]
    reason: "Legacy SNMP monitoring uses rsh until migration completes (Q3 2026)"
```

Exemptions match by substring against the ruleset `name` field. In the example above, any ruleset with "coreservices" in its name is exempt from SEC-005 (RDP/SMB restriction).

### Security Check Output

The `security-check.py` script writes a JSON report (`security-report.json`) consumed by the PR comment renderer:

```json
{
  "findings": [
    {
      "file": "scopes/payments-prod/cross-scope/to-shareddb.yaml",
      "rule_id": "SEC-004",
      "severity": "high",
      "action": "warn",
      "message": "Cross-scope rule missing 'justification' field",
      "context": "type: extra-scope"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 0,
    "blocked": false
  },
  "files_checked": 3
}
```

If any finding has `action: block`, the pipeline exits with a non-zero status code and the PR check fails.

---

## Traffic Evidence Pipeline

The traffic evidence pipeline is the most powerful feature of the validation workflow. When someone proposes a new rule (e.g., "allow web to db on 5432/tcp"), the pipeline queries the Illumio PCE for actual blocked traffic that matches the rule's pattern. This provides concrete evidence that the rule is needed, not just theoretically desired.

The pipeline is implemented in `action/scripts/traffic-evidence.py`.

### How It Works

For each new or changed rule in the PR, the pipeline:

1. **Extracts the rule pattern**: consumer labels, provider labels, and ports
2. **Builds a traffic query**: queries the PCE Explorer API for `blocked` and `potentially_blocked` flows matching the pattern over the configured lookback period (default 30 days)
3. **Filters matching flows**: compares flow source/destination/port against the rule's consumer/provider/service pattern
4. **Aggregates results**: counts total blocked connections, unique sources, unique destinations
5. **Renders a verdict**: "JUSTIFIED" if blocked traffic was found, flagged if not

### Intra-Scope Queries

For rules within a single scope, both the source and destination labels are constrained:

```
Rule: web (role:web) -> db (role:db) on 5432/tcp
Query: blocked/potentially_blocked flows
  where: dst port = 5432
  (label matching uses the port as primary filter,
   with source/destination hostname reporting)
```

### Extra-Scope Queries

For cross-scope rules, the destination is constrained to the target scope while the source may span scopes:

```
Rule: payments/processing -> shareddb/db on 5432/tcp
Query: blocked/potentially_blocked flows
  where: dst port = 5432
  (source workloads from payments scope,
   destination workloads in shareddb scope)
```

### Multi-Scope Queries

For global rulesets that span multiple scopes, one query is issued with port-based filtering, and results are aggregated across all matching flows.

### Verdicts

**Justified**: Blocked traffic matching the rule pattern was found. The PR comment shows the connection count, unique sources/destinations, first/last seen timestamps, and sample flows.

```
Verdict: JUSTIFIED -- 4,523 blocked connections over 30 days from 3 sources
```

**Unjustified / No Evidence**: No blocked traffic matching the rule pattern was found. This does not necessarily mean the rule is wrong -- it could be a proactive rule for a new deployment that has not generated traffic yet. The PR comment flags it for human review.

```
Warning: No blocked traffic found for rule "web-to-db" (5432/tcp)
This rule may not be needed, or the traffic has not occurred yet.
Consider: is this a proactive rule for a new deployment?
```

### Deny Rules and Traffic Evidence

For deny rules, the traffic evidence pipeline works in reverse. Instead of looking for blocked traffic (which would justify an allow rule), it looks for *allowed* traffic on the deny rule's ports. If allowed traffic exists on ports that a deny rule would block, this confirms the deny rule will have an impact and highlights what connections would be broken.

### Traffic Evidence Output

The `traffic-evidence.py` script writes a JSON report (`traffic-report.json`):

```json
{
  "evidence": [
    {
      "file": "scopes/payments-prod/intra-rules.yaml",
      "rule_name": "web-to-db",
      "ports": [5432],
      "traffic_found": true,
      "blocked_connections": 4523,
      "unique_sources": 3,
      "unique_destinations": 2,
      "sample_flows": [
        {
          "src": "web01.payments.prod",
          "dst": "db01.payments.prod",
          "port": "5432/tcp",
          "connections": 1823,
          "decision": "blocked"
        },
        {
          "src": "web02.payments.prod",
          "dst": "db01.payments.prod",
          "port": "5432/tcp",
          "connections": 1502,
          "decision": "blocked"
        }
      ],
      "verdict": "JUSTIFIED -- 4,523 blocked connections over 30 days from 3 sources"
    }
  ],
  "summary": {
    "total_rules": 2,
    "justified": 2,
    "unjustified": 0
  },
  "lookback_days": 30
}
```

---

## PR Comment Visualization

The validate-policy workflow posts a single markdown comment on each PR, updated on each push. The comment contains five sections: summary, change details, security findings, traffic evidence, and approval status.

### Full PR Comment Example

````markdown
## Illumio Policy Change Report

### Summary
| Metric | Value |
|--------|-------|
| Files changed | 3 |
| Rules added | 2 |
| Rules modified | 1 |
| Security findings | 1 warning |
| Traffic evidence | 2 of 2 rules justified |

---

### Changes

#### `scopes/payments-prod/intra-rules.yaml`

<table>
<tr><th>Change</th><th>Details</th></tr>
<tr>
<td>New Rule: web-to-db</td>
<td>

| | |
|---|---|
| **Consumers** | `role:web` (3 workloads: web01, web02, web03) |
| **Providers** | `role:db` (2 workloads: db01, db02) |
| **Services** | PostgreSQL (5432/tcp) |
| **Scope** | payments / prod (intra-scope) |

</td>
</tr>
</table>

#### `scopes/payments-prod/cross-scope/to-shareddb.yaml`

<table>
<tr><th>Change</th><th>Details</th></tr>
<tr>
<td>New Cross-Scope Rule: payments-to-shareddb</td>
<td>

| | |
|---|---|
| **From** | `app:payments, role:processing` -> `app:shareddb, role:db` |
| **Services** | PostgreSQL (5432/tcp) |
| **Type** | Extra-scope (requires database-team approval) |
| **Justification** | Payment processing requires direct DB access for transaction writes |

</td>
</tr>
</table>

---

### Security Analysis

| | Rule | Severity | Finding |
|---|---|---|---|
| Pass | SEC-001: No any-to-any | -- | Pass |
| Pass | SEC-002: No broad ports | -- | Pass |
| Pass | SEC-003: No insecure protocols | -- | Pass |
| Warn | SEC-005: RDP/SMB restricted | High | `to-shareddb.yaml` -- verify cross-scope DB access |
| Pass | SEC-006: DB ports restricted | -- | Pass (consumers scoped to role:processing) |

**Result: No blockers** (1 warning)

---

### Traffic Evidence

| Rule | Ports | Evidence | Verdict |
|---|---|---|---|
| **web-to-db** | 5432 | 4,523 blocked flows, 3 sources | Justified |
| **payments-to-shareddb** | 5432 | 891 blocked flows, 1 source | Justified |

---

### Approval Status

| Team | Scope | Status |
|------|-------|--------|
| @org/payments-team | `payments-prod` (owner) | Author |
| @org/database-team | `shareddb-prod` (affected) | Review required |
| @org/security-team | Cross-scope review | Review required |

---

<sub>Generated by Illumio Policy GitOps</sub>
````

### Comment Update Behavior

The workflow searches for an existing comment containing "Illumio Policy Change Report" on the PR. If found, it updates that comment in place rather than creating a new one. This keeps the PR thread clean -- there is always exactly one policy report comment, reflecting the latest state.

---

## GitHub Actions Workflows

Two workflow files live in the customer's policy repository under `.github/workflows/`.

### validate-policy.yml (Runs on PR)

**Trigger:** Pull request opened or updated against `main`, when files under `scopes/`, `ip-lists/`, or `services/` are changed.

**Permissions:** `contents: read`, `pull-requests: write` (to post the PR comment).

**Steps:**

1. **Checkout** with `fetch-depth: 0` (full history needed for `git diff` against main)
2. **Setup Python 3.12** and install dependencies (`illumio`, `pyyaml`, `requests`)
3. **Detect changed files** using `git diff --name-only origin/main...HEAD`
4. **YAML lint** -- parses every changed YAML file with `yaml.safe_load()`. If any file fails to parse, the step fails
5. **Security check** -- runs `security-check.py` with the list of changed files. Outputs `security-report.json`. Runs with `continue-on-error: true` so the PR comment is still posted
6. **Traffic evidence** -- runs `traffic-evidence.py` with the list of changed files and a 30-day lookback. Requires PCE credentials from GitHub Secrets. Outputs `traffic-report.json`. Runs with `continue-on-error: true`
7. **Render PR comment** -- uses `actions/github-script@v7` to read both JSON reports and render the markdown comment. Finds and updates existing comments
8. **Fail on critical** -- if the security check step failed (critical findings), this step exits non-zero to block the PR

### provision-policy.yml (Runs on Merge)

**Trigger:** Push to `main` branch when files under `scopes/`, `ip-lists/`, or `services/` are changed.

**Permissions:** `contents: read`.

**Environment:** `production` -- configure environment protection rules in GitHub Settings for an additional manual approval gate if desired.

**Steps:**

1. **Checkout** with `fetch-depth: 2` (need previous commit for diff)
2. **Setup Python 3.12** and install dependencies (`illumio`, `pyyaml`)
3. **Detect changed files** using `git diff --name-only HEAD~1`
4. **Provision to PCE** -- runs `provision.py` with the list of changed files. Default mode is `draft` (creates objects in draft policy). Change to `--mode active` for automatic provisioning to active policy

**Required GitHub Secrets:**

| Secret | Description |
|--------|-------------|
| `PCE_HOST` | PCE hostname (e.g., `https://pce.example.com`) |
| `PCE_PORT` | PCE port (e.g., `8443`) |
| `PCE_ORG_ID` | PCE organization ID (usually `1`) |
| `PCE_API_KEY` | API key username |
| `PCE_API_SECRET` | API key secret |

---

## Plugin Configuration

The plugin is configured through environment variables, set when installing via plugger.

### Plugin Environment Variables

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `PCE_HOST` | string | yes | -- | PCE URL (e.g., `https://pce.example.com`) |
| `PCE_PORT` | string | no | `8443` | PCE API port |
| `PCE_ORG_ID` | string | no | `1` | PCE organization ID |
| `PCE_API_KEY` | string | yes | -- | PCE API key (username) |
| `PCE_API_SECRET` | string | yes | -- | PCE API secret (password) |
| `PCE_TLS_SKIP_VERIFY` | bool | no | `true` | Skip TLS certificate verification for PCE |
| `GIT_REPO_URL` | string | yes | -- | Git repository URL (HTTPS or SSH) |
| `GIT_TOKEN` | string | yes | -- | Personal access token for HTTPS auth |
| `GIT_BRANCH` | string | no | `main` | Target branch for sync operations |
| `GIT_PROVIDER` | string | no | `github` | Git provider: `github`, `gitlab`, or `bitbucket` |
| `SYNC_MODE` | string | no | `export` | Sync direction: `export`, `provision`, or `bidirectional` |
| `SCAN_INTERVAL` | int | no | `3600` | Seconds between sync cycles |
| `AUTO_PROVISION` | bool | no | `false` | Auto-provision draft to active after Git-to-PCE sync |
| `DRIFT_ALERT` | bool | no | `true` | Enable drift detection alerts |
| `EXPORT_AS_PR` | bool | no | `false` | When true, export writes to a new branch and opens a PR instead of committing directly to the main branch. Recommended for enforcing review on all policy changes including PCE GUI edits. |
| `DATA_DIR` | string | no | `/data` | Persistent storage directory for Git clone and state |
| `HTTP_PORT` | int | no | `8080` | Port for the dashboard HTTP server |

### Policy Repository Config (`.illumio/config.yaml`)

This file lives in the customer's policy repository and configures the GitHub Actions pipeline behavior:

```yaml
pce:
  host: pce.example.com
  port: 8443
  org_id: 1

policy:
  export_rulesets: true
  export_ip_lists: true
  export_services: true
  export_labels: false         # Labels are usually managed outside policy-as-code

  provision_mode: draft        # draft | active
  provision_on_merge: true

security:
  block_on_critical: true      # Block PR on critical findings
  block_on_high: false         # Do not block on high findings (warn only)
  require_traffic_evidence: false  # If true, rules without evidence are flagged

traffic:
  lookback_days: 30            # How far back to query for blocked traffic
  min_connections: 10          # Minimum blocked connections to consider "evidence"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pce.host` | string | -- | PCE hostname (credentials come from GitHub Secrets) |
| `pce.port` | int | `8443` | PCE port |
| `pce.org_id` | int | `1` | PCE organization ID |
| `policy.export_rulesets` | bool | `true` | Export rulesets from PCE |
| `policy.export_ip_lists` | bool | `true` | Export IP lists from PCE |
| `policy.export_services` | bool | `true` | Export services from PCE |
| `policy.export_labels` | bool | `false` | Export label definitions (usually not needed) |
| `policy.provision_mode` | string | `draft` | `draft` creates objects in draft policy; `active` auto-provisions |
| `policy.provision_on_merge` | bool | `true` | Run provisioning when PRs merge to main |
| `security.block_on_critical` | bool | `true` | Fail the PR check on critical security findings |
| `security.block_on_high` | bool | `false` | Fail the PR check on high security findings |
| `security.require_traffic_evidence` | bool | `false` | Flag rules without traffic evidence |
| `traffic.lookback_days` | int | `30` | Number of days to query for traffic history |
| `traffic.min_connections` | int | `10` | Minimum blocked connections for evidence to count |

---

## Sync Modes

The plugin supports three sync modes, controlled by the `SYNC_MODE` environment variable.

### Export Mode (`export`) -- PCE to Git

The default mode. The plugin periodically fetches all policy objects from the PCE and writes them as YAML files to the Git repository. This is the "bootstrap" mode used to initially populate the policy repo and to keep it in sync as the source-of-truth transition happens.

**When to use:**
- Initial setup: exporting existing PCE policy to Git for the first time
- During transition: while teams are still making some changes in the PCE GUI
- Ongoing: to keep Git updated if the PCE is still the primary source of truth

**What happens each cycle:**
1. `git pull` to get the latest from remote
2. Refresh label/service/IP list caches from PCE
3. Fetch all rulesets, IP lists, and services from PCE active policy
4. Convert each object to YAML using `PolicySerializer`
5. Write YAML files to the appropriate scope directories using `ScopeMapper`
6. Auto-generate `_scope.yaml` for new scope directories
7. Auto-generate `CODEOWNERS` from scope ownership
8. `git commit` and `git push`

### Provision Mode (`provision`) -- Git to PCE

The reverse direction. The plugin reads YAML files from the Git repository and creates or updates the corresponding objects in the PCE draft policy.

**When to use:**
- After Git becomes the source of truth -- the plugin provisions changes to PCE
- As part of the GitHub Actions provisioning workflow (though the workflow usually calls `provision.py` directly)
- For bulk import scenarios

**What happens each cycle:**
1. `git pull` to get the latest from remote
2. Refresh all caches for label/service resolution
3. Build a map of existing PCE objects (by name) for update-vs-create detection
4. Provision services first (rulesets may reference them)
5. Provision IP lists
6. Provision rulesets: resolve scope labels from `_scope.yaml`, convert YAML actors/services to PCE HREFs
7. If `AUTO_PROVISION=true`, execute `POST /sec_policy` to promote draft to active

**Provisioning order matters:** Services and IP lists are provisioned before rulesets because rulesets may contain references to services and IP lists by name. The plugin resolves these names to HREFs during import.

### Bidirectional Mode (`bidirectional`)

Runs both export and provision in each cycle. Use with caution -- this mode is intended for environments transitioning between PCE-managed and Git-managed policy.

**When to use:**
- During a transition period where some teams use the PCE GUI and others use Git
- Not recommended for long-term use due to potential sync loops

**Loop prevention:** Bot commits are identified by the author `policy-gitops@illumio.plugger`. The plugin should be configured to ignore its own commits during import.

### Drift Detection

Drift detection runs after the sync operation (when `DRIFT_ALERT=true`). It compares the Git repository state against the PCE active policy and identifies four categories:

| Status | Meaning |
|--------|---------|
| `in_sync` | Object matches between Git and PCE |
| `drift_modified` | Object exists in both but differs |
| `git_only` | Object exists in Git but not in PCE active policy |
| `pce_only` | Object exists in PCE but not in Git |

Drift items are displayed on the plugin dashboard under the "Drift Report" tab.

**Recommended approach for drift:** When drift is detected (e.g., someone made a change in the PCE GUI), the plugin should auto-create a reconciliation PR that brings Git back in sync with the PCE. This ensures all changes are tracked in Git regardless of origin.

---

## Getting Started

This section walks you from a fresh clone of this repo to a fully working policy-as-code pipeline. You will end up with:

- A **policy repository** (a new GitHub repo) holding your PCE policy as YAML
- The **plugin** running and syncing your PCE policy into that repo
- **GitHub Actions** validating every PR with security checks and traffic evidence
- **Branch protection** enforcing team approvals via CODEOWNERS

Total setup time: ~30 minutes.

---

### What You Need

| Requirement | Notes |
|---|---|
| Illumio PCE | API key + secret, hostname, org ID |
| GitHub organization | Teams must exist before CODEOWNERS can reference them |
| GitHub Personal Access Token (PAT) | Needs `repo` scope — see Step 0 |
| Docker | To build and run the plugin container |
| `plugger` CLI (optional) | Recommended for production; Docker alone works for testing |

---

### Step 0: Create a GitHub Personal Access Token

The plugin needs a PAT to clone the policy repo and push commits. The GitHub Actions workflows use a separate token (the built-in `GITHUB_TOKEN`) for posting PR comments — you do not need to manage that one.

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)**
2. Click **Generate new token (classic)**
3. Set an expiration (90 days recommended for testing; shorter for production with rotation)
4. Select scope: **`repo`** (full repository access — needed for clone, push, and PR creation)
5. Click **Generate token** and save it — you will not see it again

This token is used in two places: as `GIT_TOKEN` for the plugin, and as a fallback if the workflow needs to write to the repo beyond `GITHUB_TOKEN`'s default permissions.

---

### Step 1: Create the Policy Repository

The policy repository is a new, dedicated GitHub repo that holds only YAML policy files. It is not this repo — it is the repo the plugin writes to and your teams open PRs against.

```bash
# Create a new private repo in your GitHub org
gh repo create YOUR_ORG/illumio-policy --private --clone
cd illumio-policy

# Copy all template files (including hidden directories)
GITOPS_DIR=/path/to/illumio-policy-gitops
cp -r "$GITOPS_DIR/template/." .

# Copy the action scripts the workflows depend on
mkdir -p .github/scripts
cp "$GITOPS_DIR/action/scripts/"*.py .github/scripts/

# Initial commit
git add -A
git commit -m "Initialize policy repository from template"
git push -u origin main
```

Verify the repo now contains:
```
.github/workflows/validate-policy.yml
.github/workflows/provision-policy.yml
.github/scripts/security-check.py
.github/scripts/traffic-evidence.py
.illumio/config.yaml
.illumio/security-rules.yaml
CODEOWNERS
scopes/_global/
```

---

### Step 2: Configure `.illumio/config.yaml`

Edit `.illumio/config.yaml` in the policy repo with your PCE connection details:

```yaml
pce:
  host: pce.example.com   # hostname only, no https://
  port: 8443
  org_id: 1

policy:
  provision_mode: draft        # Start with draft; switch to active when confident
  provision_on_merge: true

security:
  block_on_critical: true
  block_on_high: false

traffic:
  lookback_days: 30
  min_connections: 10
```

Commit and push this change before proceeding.

---

### Step 3: Add GitHub Actions Secrets

In the **policy repository** (not this repo): **Settings → Secrets and variables → Actions → New repository secret**

| Secret name | Value |
|---|---|
| `PCE_HOST` | `https://pce.example.com` (with protocol) |
| `PCE_PORT` | `8443` |
| `PCE_ORG_ID` | `1` |
| `PCE_API_KEY` | Your API key username |
| `PCE_API_SECRET` | Your API key secret |

These secrets are used by `validate-policy.yml` (traffic evidence) and `provision-policy.yml` (provisioning on merge).

---

### Step 4: Enable Branch Protection

In the policy repository: **Settings → Branches → Add rule** for the `main` branch:

- [x] Require a pull request before merging
- [x] Require approvals (1 minimum)
- [x] Require review from Code Owners
- [x] Require status checks to pass → add **"Policy Validation"**
- [x] Do not allow bypassing the above settings

This ensures no policy change reaches `main` without both a passing CI check and the required team approvals.

---

### Step 5: Run the Plugin — Initial Export

The plugin connects to your PCE, reads all rulesets, IP lists, and services, and writes them as YAML files into the policy repo. Run it once in `export` mode to bootstrap the repository.

#### Option A: Docker (fastest for testing)

```bash
# Build the container from this repo
cd /path/to/illumio-policy-gitops/plugin
docker build -t policy-gitops:latest .

docker run -d \
  --name policy-gitops \
  -e PCE_HOST="https://pce.example.com" \
  -e PCE_PORT="8443" \
  -e PCE_ORG_ID="1" \
  -e PCE_API_KEY="your-api-key" \
  -e PCE_API_SECRET="your-api-secret" \
  -e GIT_REPO_URL="https://github.com/YOUR_ORG/illumio-policy.git" \
  -e GIT_TOKEN="ghp_your_token_here" \
  -e SYNC_MODE="export" \
  -e SCAN_INTERVAL="60" \
  -p 8080:8080 \
  policy-gitops:latest

# Watch the initial export
docker logs -f policy-gitops
```

#### Option B: Plugger

```bash
cd /path/to/illumio-policy-gitops/plugin
docker build -t policy-gitops:latest .
plugger install plugin.yaml

plugger config set policy-gitops PCE_HOST      "https://pce.example.com"
plugger config set policy-gitops PCE_PORT      "8443"
plugger config set policy-gitops PCE_ORG_ID    "1"
plugger config set policy-gitops PCE_API_KEY   "your-api-key"
plugger config set policy-gitops PCE_API_SECRET "your-api-secret"
plugger config set policy-gitops GIT_REPO_URL  "https://github.com/YOUR_ORG/illumio-policy.git"
plugger config set policy-gitops GIT_TOKEN     "ghp_your_token_here"
plugger config set policy-gitops SYNC_MODE     "export"
plugger config set policy-gitops SCAN_INTERVAL "60"

plugger start policy-gitops
plugger logs policy-gitops -f
```

#### Verify the export worked

```bash
# Dashboard should show status and last_export timestamp
curl http://localhost:8080/api/state | python3 -m json.tool

# Check the policy repo on GitHub — scopes/ directories should have appeared
cd illumio-policy && git pull && ls scopes/
# Expected: _global/  app-payments_env-prod/  app-shareddb_env-prod/  ...
```

The export is complete when you see directories under `scopes/` in the policy repo and the plugin logs show `Export complete`.

---

### Step 6: Update CODEOWNERS

After the initial export, the plugin auto-generates a `CODEOWNERS` file based on the directories it created. Review it and assign your actual GitHub teams.

The generated file will have placeholder entries like:

```
scopes/app-payments_env-prod/   # TODO: assign team
```

Edit it to assign real teams:

```
# Global policy -- security team reviews all infrastructure changes
scopes/_global/                  @your-org/security-team
ip-lists/                        @your-org/security-team
services/                        @your-org/security-team
.illumio/                        @your-org/security-team

# Per-scope ownership -- directory name encodes the label key=value pairs
scopes/app-payments_env-prod/    @your-org/payments-team
scopes/app-shareddb_env-prod/    @your-org/database-team
scopes/app-ordering_env-prod/    @your-org/ordering-team

# Cross-scope rules always require security team review
scopes/*/cross-scope/            @your-org/security-team
scopes/*/inbound/                @your-org/security-team
```

Commit and push this change directly to `main` (before branch protection locks it down, or via admin bypass).

---

### Step 7: Test the PR Workflow

Create a test branch and open a PR to verify the full pipeline works end-to-end:

```bash
cd illumio-policy
git pull
git checkout -b test/validate-pipeline

# Make a trivial change to any ruleset -- add a description field, change nothing structural
# Example: pick any file the export created
SCOPE_FILE=$(find scopes -name "*.yaml" ! -name "_scope.yaml" | head -1)
echo "  # test" >> "$SCOPE_FILE"

git add "$SCOPE_FILE"
git commit -m "test: trigger validation pipeline"
git push -u origin test/validate-pipeline

gh pr create --title "Test: validate pipeline" \
  --body "Smoke test to verify security check, traffic evidence, and PR comment all work."
```

Within 2-3 minutes you should see on the PR:
- A comment from the workflow with the security analysis table and traffic evidence section
- A **Policy Validation** status check (green if no critical findings, red if SEC-001–SEC-008 fired)
- CODEOWNERS review requests sent to the appropriate teams

If the check is green, close the PR without merging. The pipeline is working.

---

### Step 8: Switch to Ongoing Sync

Once the initial export is done and the PR workflow is verified, switch the plugin to the mode that fits your workflow:

| Goal | `SYNC_MODE` | `EXPORT_AS_PR` | Notes |
|---|---|---|---|
| Track PCE, no review gate on GUI changes | `export` | `false` | Default; exports commit directly to main |
| Track PCE, enforce review on all changes | `export` | `true` | **Recommended** — exports open a PR; validate pipeline runs; team approves before merge |
| Apply Git changes to PCE (Git is source of truth) | `provision` | n/a | Provisions on merge via GitHub Actions; plugin syncs the rest |
| Transition period (both directions) | `bidirectional` | — | Use temporarily; avoid long-term to prevent sync loops |

For most teams: use `SYNC_MODE=export` with `EXPORT_AS_PR=true`. Every PCE change — whether made through the GUI or via API — surfaces as a PR and goes through the same review and validation pipeline before landing on `main`.

---

## Standalone Project Roadmap

When extracted from the plugger monorepo into its own standalone project, the repository structure would be:

```
illumio-policy-gitops/
|
+-- README.md                              <- This documentation
+-- LICENSE
|
+-- plugin/                                <- The plugger plugin (PCE sync engine)
|   +-- main.py
|   +-- Dockerfile
|   +-- .plugger/metadata.yaml
|   +-- plugin.yaml
|
+-- action/                                <- Reusable GitHub Action
|   +-- action.yml                         <- GitHub Action definition
|   +-- scripts/
|   |   +-- lint-policy.py
|   |   +-- security-check.py
|   |   +-- traffic-evidence.py
|   |   +-- provision.py
|   |   +-- render-comment.py
|   +-- templates/
|       +-- pr-comment.md.j2              <- Jinja2 template for PR comment
|
+-- template/                              <- Starter repo template
|   +-- .github/
|   |   +-- workflows/
|   |       +-- validate-policy.yml
|   |       +-- provision-policy.yml
|   +-- .illumio/
|   |   +-- config.yaml
|   |   +-- security-rules.yaml
|   |   +-- team-config.yaml
|   +-- scopes/
|   |   +-- _global/
|   +-- ip-lists/
|   +-- services/
|   +-- labels/
|   +-- CODEOWNERS
|   +-- README.md
|
+-- docs/
    +-- getting-started.md
    +-- security-rules-reference.md
    +-- yaml-format.md
    +-- multi-team-workflows.md
```

### Reusable GitHub Action

The `action/` directory would be published as a reusable GitHub Action. Instead of copying scripts into each policy repo, customers would reference the action:

```yaml
# In the customer's validate-policy.yml
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: alexgoller/illumio-policy-gitops/action@v1
        with:
          pce-host: ${{ secrets.PCE_HOST }}
          pce-port: ${{ secrets.PCE_PORT }}
          pce-api-key: ${{ secrets.PCE_API_KEY }}
          pce-api-secret: ${{ secrets.PCE_API_SECRET }}
          mode: validate       # validate | provision
          lookback-days: 30
```

This simplifies adoption -- customers only need the workflow YAML file and CODEOWNERS, not the entire scripts directory.

### Future Capabilities

- **GitLab MR support** -- CODEOWNERS works in GitLab too; the pipeline scripts are provider-agnostic
- **Bitbucket support** -- reviewer rules instead of CODEOWNERS
- **Slack/Teams notifications** -- alert when cross-scope PRs need review
- **Terraform bridge** -- export policy as Terraform HCL for teams using Terraform
- **Policy simulation** -- "what would change" preview using PCE draft mode
- **Auto-remediation PRs** -- when drift is detected, auto-create a PR to reconcile
- **Label management** -- optionally manage labels through the same GitOps workflow
- **Policy validation DSL** -- custom validation rules beyond the built-in SEC-001 through SEC-008

---

## Dependencies

### Plugin (main.py)

| Package | Version | Purpose |
|---------|---------|---------|
| `illumio` | latest | PCE SDK -- REST API client |
| `requests` | latest | HTTP client for Git provider APIs (PR creation) |
| `pyyaml` | latest | YAML serialization/deserialization |
| `gitpython` | latest | Listed in requirements.txt (plugin uses subprocess git instead) |

### GitHub Actions Scripts

| Package | Purpose |
|---------|---------|
| `illumio` | PCE SDK for traffic evidence queries |
| `pyyaml` | YAML parsing |
| Standard library | `argparse`, `json`, `os`, `sys`, `datetime` |

### Infrastructure

- Python 3.12+
- Git (installed in the Docker image)
- Docker (for building the plugin container)
- GitHub Actions (or equivalent CI/CD)

---

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Bidirectional sync loops | Bot commits identified by author (`policy-gitops@illumio.plugger`); ignored on import |
| Emergency changes bypassing Git | Drift detector flags out-of-band changes; auto-create reconciliation PR |
| Label HREFs differ between export and import | YAML uses human-readable `key:value` pairs; HREFs resolved at provision time via cache |
| Large policy repos | Only export changed objects; Git handles scale well |
| Git merge conflicts | Scope-per-directory minimizes conflicts; each team edits their own directory |
| CODEOWNERS not enforced | Branch protection with "Require review from Code Owners" must be enabled |
| Traffic evidence query slow | Cache results; only query for new/changed rules |
| Secrets exposure | API keys stored in GitHub Secrets; never displayed in PR comments; only traffic counts and workload names shown |
| PCE unavailable during PR validation | Traffic evidence and security checks run with `continue-on-error: true`; PR comment still posted with available data |

---

## API Reference

The plugin serves an HTTP API on port 8080 alongside the dashboard.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard HTML page |
| `GET` | `/healthz` | Health check endpoint (returns `{"status": "healthy"}`) |
| `GET` | `/api/state` | Full plugin state as JSON (status, counters, drift items, history) |
| `GET` | `/api/drift` | Trigger a drift check (returns immediately, runs async) |
| `POST` | `/api/export` | Trigger an export cycle (PCE to Git) |
| `POST` | `/api/provision` | Trigger a provision cycle (Git to PCE) |
| `POST` | `/api/drift` | Trigger a drift check |

The dashboard auto-refreshes every 15 seconds by polling `/api/state`.

---

## License

Apache-2.0
