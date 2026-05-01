#!/usr/bin/env python3
"""
Security check for Illumio policy YAML files.

Evaluates changed policy files against configurable security rules.
Outputs a JSON report for the PR comment renderer.

Usage:
  python3 security-check.py --changed-files "scopes/foo/bar.yaml" --output report.json
"""

import argparse
import json
import os
import sys

import yaml


# Default security rules (overridden by .illumio/security-rules.yaml)
DEFAULT_RULES = [
    {
        "id": "SEC-001",
        "name": "No any-to-any rules",
        "severity": "critical",
        "action": "block",
        "scope_filter": "unscoped",
        "description": "Rules with 'all workloads' on both providers and consumers defeat micro-segmentation.",
    },
    {
        "id": "SEC-002",
        "name": "No broad port ranges",
        "severity": "critical",
        "action": "block",
        "description": "Port ranges exceeding 1000 ports are too permissive.",
    },
    {
        "id": "SEC-003",
        "name": "No insecure protocols",
        "severity": "critical",
        "action": "block",
        "ports": [21, 23, 69, 513, 514],
        "description": "FTP, Telnet, TFTP, rlogin, rsh are insecure. Use SSH/SFTP.",
    },
    {
        "id": "SEC-004",
        "name": "Cross-scope rules need justification",
        "severity": "high",
        "action": "warn",
        "description": "Extra-scope rules should include a justification field.",
    },
    {
        "id": "SEC-005",
        "name": "RDP/SMB restricted",
        "severity": "high",
        "action": "warn",
        "ports": [3389, 445],
        "description": "RDP and SMB are lateral movement vectors.",
    },
    {
        "id": "SEC-006",
        "name": "Database ports scoped",
        "severity": "high",
        "action": "warn",
        "ports": [5432, 3306, 1433, 1521, 27017],
        "description": "Database ports should only be accessible from specific consumer roles.",
    },
    {
        "id": "SEC-007",
        "name": "IP List broad CIDR",
        "severity": "medium",
        "action": "warn",
        "description": "IP lists with /8 or broader CIDRs are very permissive.",
    },
    {
        "id": "SEC-008",
        "name": "Overly broad rule consumer",
        "severity": "high",
        "action": "warn",
        "description": (
            "Rules with 'All Workloads' or an Any/RFC-1918 IP list as consumer "
            "and no role label on providers grant network access to everyone. "
            "Restrict consumers to a specific role or label."
        ),
    },
]


def load_security_rules():
    """Load security rules from .illumio/security-rules.yaml or use defaults."""
    rules_path = os.path.join(os.getcwd(), ".illumio", "security-rules.yaml")
    if not os.path.exists(rules_path):
        return DEFAULT_RULES, []

    with open(rules_path) as f:
        config = yaml.safe_load(f) or {}

    # Merge: start with defaults, override/extend with config file entries
    config_rules = config.get("rules", [])
    if not config_rules:
        merged = DEFAULT_RULES
    else:
        default_by_id = {r["id"]: dict(r) for r in DEFAULT_RULES}
        for cr in config_rules:
            rid = cr.get("id", "")
            if rid in default_by_id:
                default_by_id[rid].update(cr)
            else:
                default_by_id[rid] = cr
        merged = list(default_by_id.values())

    # Filter out disabled rules
    active = [r for r in merged if r.get("enabled", True)]
    return active, config.get("exemptions", [])


def _ruleset_is_scoped(data: dict) -> bool:
    """Return True if the ruleset has a non-empty scope (i.e. it is not global)."""
    for scope_entry in data.get("scopes", []):
        if scope_entry:
            return True
    return False


def check_rule_any_to_any(rule_data: dict, is_scoped: bool) -> bool:
    """SEC-001: Check for any-to-any rules.

    ams→ams in a scoped ruleset is intra-scope ringfencing (valid pattern).
    ams→ams in a global/unscoped ruleset is true any-to-any (dangerous).
    """
    providers = rule_data.get("providers", [])
    consumers = rule_data.get("consumers", [])
    prov_ams = any(p.get("actors") == "ams" for p in providers if isinstance(p, dict))
    cons_ams = any(c.get("actors") == "ams" for c in consumers if isinstance(c, dict))
    if not (prov_ams and cons_ams):
        return False
    return not is_scoped


def check_broad_port_range(services):
    """SEC-002: Check for port ranges > 1000."""
    for svc in services:
        if isinstance(svc, dict):
            port = svc.get("port", 0)
            to_port = svc.get("to_port", 0)
            if port and to_port and (to_port - port) > 1000:
                return True
    return False


def check_ports(services, blocked_ports):
    """Check if any service uses a blocked port."""
    found = []
    for svc in services:
        if isinstance(svc, dict):
            port = svc.get("port")
            if port in blocked_ports:
                found.append(port)
    return found


def check_broad_cidr(ip_ranges):
    """SEC-007: Check for very broad CIDRs."""
    for r in ip_ranges:
        if isinstance(r, dict):
            from_ip = r.get("from_ip", "")
            if "/" in from_ip:
                try:
                    prefix = int(from_ip.split("/")[1])
                    if prefix <= 8:
                        return from_ip
                except ValueError:
                    pass
    return None


# Names of well-known catch-all IP lists (case-insensitive prefix match)
_BROAD_IP_LIST_NAMES = {"any", "all", "rfc1918", "0.0.0.0"}


def check_broad_consumer(rule_data: dict) -> bool:
    """SEC-008: Consumer is 'All Workloads' or a broad IP list with no role on providers."""
    consumers = rule_data.get("consumers", [])
    providers = rule_data.get("providers", [])

    broad_consumer = False
    for c in consumers:
        if not isinstance(c, dict):
            continue
        if c.get("actors") == "ams":
            broad_consumer = True
            break
        ipl = c.get("ip_list", {})
        if isinstance(ipl, dict):
            name = ipl.get("name", "").lower()
            if any(name.startswith(p) for p in _BROAD_IP_LIST_NAMES):
                broad_consumer = True
                break

    if not broad_consumer:
        return False

    for p in providers:
        if not isinstance(p, dict):
            continue
        lbl = p.get("label", {})
        if isinstance(lbl, dict) and "role" in lbl:
            return False

    return True


def _is_rule_applicable(rule_cfg: dict, is_scoped: bool) -> bool:
    """Check scope_filter to decide if a rule applies to this ruleset."""
    scope_filter = rule_cfg.get("scope_filter", "")
    if scope_filter == "unscoped":
        return not is_scoped
    if scope_filter == "scoped":
        return is_scoped
    return True


def _is_scope_exempt(data: dict, exemptions: list, rule_id: str) -> bool:
    """Check scope-pattern exemptions (env=dev style)."""
    for ex in exemptions:
        pattern = ex.get("scope_pattern", "")
        if not pattern:
            continue
        # Match against scope label values in the YAML
        for scope_entry in data.get("scopes", []):
            for item in scope_entry:
                if isinstance(item, dict) and "label" in item:
                    lbl = item["label"]
                    if isinstance(lbl, dict):
                        for k, v in lbl.items():
                            if f"{k}={v}" == pattern or str(v) == pattern:
                                if rule_id in ex.get("exempt_rules", []):
                                    return True
    return False


def analyze_file(filepath, rules, exemptions):
    """Analyze a single YAML policy file against security rules."""
    findings = []

    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        findings.append({
            "file": filepath,
            "rule_id": "PARSE",
            "severity": "critical",
            "action": "block",
            "message": f"Failed to parse YAML: {e}",
        })
        return findings

    if not isinstance(data, dict):
        return findings

    is_scoped = _ruleset_is_scoped(data)

    # Build per-file exempt set from ruleset_pattern and scope_pattern exemptions
    ruleset_name = data.get("name", "")
    exempt_rules = set()
    for ex in exemptions:
        rp = ex.get("ruleset_pattern", "")
        if rp and rp in ruleset_name:
            exempt_rules.update(ex.get("exempt_rules", []))
        # Scope-pattern exemptions are checked per-rule below via _is_scope_exempt

    # Build a lookup of active rules by id for quick access to config
    rule_cfg_by_id = {r["id"]: r for r in rules}

    for rule_data in data.get("rules", []):
        if not isinstance(rule_data, dict):
            continue

        rule_name = rule_data.get("name", "(unnamed)")
        services = rule_data.get("services", [])

        # SEC-001: any-to-any (only on unscoped rulesets by default)
        if "SEC-001" not in exempt_rules and "SEC-001" in rule_cfg_by_id:
            cfg = rule_cfg_by_id["SEC-001"]
            if (_is_rule_applicable(cfg, is_scoped)
                    and not _is_scope_exempt(data, exemptions, "SEC-001")
                    and check_rule_any_to_any(rule_data, is_scoped)):
                findings.append({
                    "file": filepath,
                    "rule_id": "SEC-001",
                    "severity": cfg.get("severity", "critical"),
                    "action": cfg.get("action", "block"),
                    "message": f"Rule '{rule_name}' allows any-to-any traffic (unscoped ruleset)",
                    "context": "providers and consumers both use 'actors: ams' with no scope restriction",
                })

        # SEC-002: broad port range
        if "SEC-002" not in exempt_rules and "SEC-002" in rule_cfg_by_id:
            cfg = rule_cfg_by_id["SEC-002"]
            if (_is_rule_applicable(cfg, is_scoped)
                    and not _is_scope_exempt(data, exemptions, "SEC-002")
                    and check_broad_port_range(services)):
                findings.append({
                    "file": filepath,
                    "rule_id": "SEC-002",
                    "severity": cfg.get("severity", "critical"),
                    "action": cfg.get("action", "block"),
                    "message": f"Rule '{rule_name}' has a port range exceeding 1000 ports",
                })

        # SEC-003: insecure protocols
        if "SEC-003" not in exempt_rules and "SEC-003" in rule_cfg_by_id:
            cfg = rule_cfg_by_id["SEC-003"]
            ports = cfg.get("ports", [21, 23, 69, 513, 514])
            if (_is_rule_applicable(cfg, is_scoped)
                    and not _is_scope_exempt(data, exemptions, "SEC-003")):
                insecure = check_ports(services, ports)
                if insecure:
                    findings.append({
                        "file": filepath,
                        "rule_id": "SEC-003",
                        "severity": cfg.get("severity", "critical"),
                        "action": cfg.get("action", "block"),
                        "message": f"Rule '{rule_name}' allows insecure ports: {insecure}",
                    })

        # SEC-005: RDP/SMB
        if "SEC-005" not in exempt_rules and "SEC-005" in rule_cfg_by_id:
            cfg = rule_cfg_by_id["SEC-005"]
            ports = cfg.get("ports", [3389, 445])
            if (_is_rule_applicable(cfg, is_scoped)
                    and not _is_scope_exempt(data, exemptions, "SEC-005")):
                risky = check_ports(services, ports)
                if risky:
                    findings.append({
                        "file": filepath,
                        "rule_id": "SEC-005",
                        "severity": cfg.get("severity", "high"),
                        "action": cfg.get("action", "warn"),
                        "message": f"Rule '{rule_name}' allows RDP/SMB ports: {risky}",
                    })

        # SEC-006: DB ports without specific consumer
        if "SEC-006" not in exempt_rules and "SEC-006" in rule_cfg_by_id:
            cfg = rule_cfg_by_id["SEC-006"]
            ports = cfg.get("ports", [5432, 3306, 1433, 1521, 27017])
            if (_is_rule_applicable(cfg, is_scoped)
                    and not _is_scope_exempt(data, exemptions, "SEC-006")):
                db_ports = check_ports(services, ports)
                if db_ports:
                    consumers = rule_data.get("consumers", [])
                    has_specific = any(
                        c.get("label", {}).get("role")
                        for c in consumers if isinstance(c, dict)
                    )
                    if not has_specific:
                        findings.append({
                            "file": filepath,
                            "rule_id": "SEC-006",
                            "severity": cfg.get("severity", "high"),
                            "action": cfg.get("action", "warn"),
                            "message": f"Rule '{rule_name}' exposes DB ports {db_ports} without role-specific consumers",
                        })

    # SEC-004: cross-scope without justification
    if "SEC-004" not in exempt_rules and "SEC-004" in rule_cfg_by_id:
        cfg = rule_cfg_by_id["SEC-004"]
        if (_is_rule_applicable(cfg, is_scoped)
                and not _is_scope_exempt(data, exemptions, "SEC-004")):
            if data.get("type") == "extra-scope" or data.get("unscoped_consumers"):
                if not data.get("justification"):
                    findings.append({
                        "file": filepath,
                        "rule_id": "SEC-004",
                        "severity": cfg.get("severity", "high"),
                        "action": cfg.get("action", "warn"),
                        "message": "Cross-scope rule missing 'justification' field",
                    })

    # SEC-007: IP list broad CIDR
    if "SEC-007" not in exempt_rules and "SEC-007" in rule_cfg_by_id and "ip-lists" in filepath:
        cfg = rule_cfg_by_id["SEC-007"]
        if not _is_scope_exempt(data, exemptions, "SEC-007"):
            broad = check_broad_cidr(data.get("ip_ranges", []))
            if broad:
                findings.append({
                    "file": filepath,
                    "rule_id": "SEC-007",
                    "severity": cfg.get("severity", "medium"),
                    "action": cfg.get("action", "warn"),
                    "message": f"IP list contains very broad CIDR: {broad}",
                })

    # SEC-008: overly broad consumer (per-rule check for scopes/ files)
    if "SEC-008" not in exempt_rules and "SEC-008" in rule_cfg_by_id and "scopes" in filepath:
        cfg = rule_cfg_by_id["SEC-008"]
        if (_is_rule_applicable(cfg, is_scoped)
                and not _is_scope_exempt(data, exemptions, "SEC-008")):
            for rule_data in data.get("rules", []):
                if not isinstance(rule_data, dict):
                    continue
                if check_broad_consumer(rule_data):
                    rule_name = rule_data.get("name", "(unnamed)")
                    findings.append({
                        "file": filepath,
                        "rule_id": "SEC-008",
                        "severity": cfg.get("severity", "high"),
                        "action": cfg.get("action", "warn"),
                        "message": (
                            f"Rule '{rule_name}' has a broad consumer (All Workloads or catch-all IP list) "
                            "with no role constraint on providers"
                        ),
                    })

    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--changed-files", required=True)
    parser.add_argument("--output", default="security-report.json")
    args = parser.parse_args()

    rules, exemptions = load_security_rules()
    files = [f.strip() for f in args.changed_files.split("\n") if f.strip() and f.endswith((".yaml", ".yml"))]

    all_findings = []
    for filepath in files:
        if os.path.exists(filepath):
            all_findings.extend(analyze_file(filepath, rules, exemptions))

    summary = {
        "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
        "high": sum(1 for f in all_findings if f["severity"] == "high"),
        "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
        "blocked": any(f["action"] == "block" for f in all_findings),
    }

    report = {"findings": all_findings, "summary": summary, "files_checked": len(files)}

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Security check: {len(files)} files, {len(all_findings)} findings "
          f"({summary['critical']}C {summary['high']}H {summary['medium']}M)")

    if summary["blocked"]:
        print("BLOCKED: Critical security findings found")
        sys.exit(1)
    else:
        print("PASSED: No blocking findings")


if __name__ == "__main__":
    main()
