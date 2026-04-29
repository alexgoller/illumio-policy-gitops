#!/usr/bin/env python3
"""
Traffic evidence collector for Illumio policy PRs.

For each new/changed rule in a PR, queries the PCE for blocked traffic
that matches the rule's consumer/provider/service pattern. This provides
evidence that a rule is justified by actual traffic.

Config is read from .illumio/traffic-evidence.yaml when present.

Usage:
  python3 traffic-evidence.py --changed-files "scopes/foo/bar.yaml" \
    --lookback-days 30 --output traffic-report.json
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta

import yaml

try:
    from illumio import PolicyComputeEngine
    from illumio.explorer import TrafficQuery
    HAS_ILLUMIO = True
except ImportError:
    HAS_ILLUMIO = False


def _get_base_data(filepath: str, diff_base: str) -> dict:
    try:
        raw = subprocess.check_output(
            ["git", "show", f"{diff_base}:{filepath}"],
            stderr=subprocess.DEVNULL,
        )
        return yaml.safe_load(raw) or {}
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {}


def _diff_rules(base_data: dict, current_data: dict) -> dict[str, str]:
    """Return {rule_name: 'deleted'} for rules present in base but not current."""
    base = {r.get("name", "(unnamed)") for r in base_data.get("rules", []) if isinstance(r, dict)}
    current = {r.get("name", "(unnamed)") for r in current_data.get("rules", []) if isinstance(r, dict)}
    return {name: "deleted" for name in base - current}


def load_traffic_config(cli_lookback_days: int) -> dict:
    """Load traffic evidence config from .illumio/traffic-evidence.yaml.

    CLI args take precedence over config file defaults.
    """
    defaults = {
        "enabled": True,
        "lookback_days": cli_lookback_days,
        "min_connections": 1,
        "scope_overrides": {},
        "thresholds": {
            "justified": 10,
            "weak_evidence": 1,
        },
        "query": {
            "policy_decisions": ["blocked", "potentially_blocked"],
            "exclude_ports": [],
        },
    }

    config_path = os.path.join(os.getcwd(), ".illumio", "traffic-evidence.yaml")
    if not os.path.exists(config_path):
        return defaults

    with open(config_path) as f:
        cfg = yaml.safe_load(f) or {}

    # Merge top-level keys; CLI lookback_days overrides file if explicitly passed
    merged = {**defaults, **cfg}
    if cli_lookback_days != 30:  # non-default CLI value wins
        merged["lookback_days"] = cli_lookback_days
    # Nested merge for thresholds and query
    merged["thresholds"] = {**defaults["thresholds"], **cfg.get("thresholds", {})}
    merged["query"] = {**defaults["query"], **cfg.get("query", {})}
    return merged


def get_scope_config(config: dict, scope_labels: dict) -> dict:
    """Return per-scope override config merged with global config."""
    overrides = config.get("scope_overrides", {})
    merged = {
        "enabled": config.get("enabled", True),
        "lookback_days": config.get("lookback_days", 30),
        "min_connections": config.get("min_connections", 1),
    }
    for pattern, override in overrides.items():
        for k, v in scope_labels.items():
            if f"{k}={v}" == pattern or str(v) == pattern:
                merged.update(override)
                break
    return merged


def load_service_port_map(repo_root: str = ".") -> dict:
    """Build name→[ports] lookup from services/*.yaml files in the repo.

    Service objects in rules are stored as {name: mysql} — the actual port
    definitions live in services/mysql.yaml as service_ports: [{port:3306}].
    Returns {} if the services directory doesn't exist (graceful degradation).
    """
    svc_dir = os.path.join(repo_root, "services")
    port_map = {}
    if not os.path.isdir(svc_dir):
        return port_map
    for fname in os.listdir(svc_dir):
        if not fname.endswith((".yaml", ".yml")):
            continue
        try:
            with open(os.path.join(svc_dir, fname)) as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                continue
            name = data.get("name", "")
            ports = [
                sp["port"]
                for sp in data.get("service_ports", [])
                if isinstance(sp, dict) and "port" in sp
            ]
            if name and ports:
                port_map[name] = ports
        except Exception:
            pass
    return port_map


def _resolve_ports(services: list, service_port_map: dict, exclude_ports: set) -> list:
    """Extract port numbers from a rule's service list.

    Handles both inline ports ({port: 3306}) and named service references
    ({name: mysql}) by looking up the name in service_port_map.
    Returns an empty list when services is empty (means All Services).
    """
    ports = []
    for svc in services:
        if not isinstance(svc, dict):
            continue
        if "port" in svc:
            p = svc["port"]
            if p not in exclude_ports:
                ports.append(p)
        elif "name" in svc:
            for p in service_port_map.get(svc["name"], []):
                if p not in exclude_ports:
                    ports.append(p)
    return ports


def get_pce():
    """Create PCE client from environment."""
    if not HAS_ILLUMIO:
        return None
    host = os.environ.get("PCE_HOST", "")
    if not host:
        return None
    pce = PolicyComputeEngine(
        url=host,
        port=os.environ.get("PCE_PORT", "8443"),
        org_id=os.environ.get("PCE_ORG_ID", "1"),
    )
    pce.set_credentials(
        username=os.environ.get("PCE_API_KEY", ""),
        password=os.environ.get("PCE_API_SECRET", ""),
    )
    pce.set_tls_settings(verify=False)
    return pce


def extract_rules_from_file(filepath):
    """Extract rules and scope labels from a YAML policy file."""
    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
    except Exception:
        return [], {}

    if not isinstance(data, dict):
        return [], {}

    # Collect scope label values for per-scope config lookup
    scope_labels = {}
    for scope_entry in data.get("scopes", []):
        for item in scope_entry:
            if isinstance(item, dict) and "label" in item:
                lbl = item["label"]
                if isinstance(lbl, dict):
                    scope_labels.update(lbl)

    ruleset_name = data.get("name") or os.path.splitext(os.path.basename(filepath))[0]

    rules = []
    for rule in data.get("rules", []):
        if isinstance(rule, dict):
            rules.append({
                "file": filepath,
                "ruleset_name": ruleset_name,
                "name": rule.get("name", "(unnamed)"),
                "consumers": rule.get("consumers", []),
                "providers": rule.get("providers", []),
                "services": rule.get("services", []),
                "scope_labels": scope_labels,
            })

    # Cross-scope rule format
    if data.get("type") == "extra-scope":
        consumers = data.get("requester", {}).get("consumers", [])
        providers = data.get("target", {}).get("providers", [])
        services = data.get("services", [])
        rules.append({
            "file": filepath,
            "ruleset_name": ruleset_name,
            "name": data.get("name", "(unnamed)"),
            "consumers": consumers,
            "providers": providers,
            "services": services,
            "scope_labels": scope_labels,
        })

    return rules, scope_labels


def _make_verdict(total_connections: int, thresholds: dict, lookback_days: int,
                  unique_sources: int) -> str:
    justified_threshold = thresholds.get("justified", 10)
    weak_threshold = thresholds.get("weak_evidence", 1)
    if total_connections >= justified_threshold:
        return f"JUSTIFIED — {total_connections:,} blocked connections over {lookback_days} days from {unique_sources} sources"
    elif total_connections >= weak_threshold:
        return f"WEAK EVIDENCE — only {total_connections} blocked connection(s) in {lookback_days} days"
    return f"NO EVIDENCE — 0 blocked connections in {lookback_days} days"


def query_traffic_for_rule(pce, rule: dict, scope_cfg: dict, global_config: dict,
                           service_port_map: dict = None,
                           policy_decisions: list = None) -> dict:
    """Query PCE for traffic matching a rule's pattern.

    policy_decisions defaults to blocked+potentially_blocked for new/changed rules.
    Pass ["allowed"] to assess deletion impact.
    """
    if not pce:
        return None

    lookback_days = scope_cfg.get("lookback_days", 30)
    min_connections = scope_cfg.get("min_connections", 1)
    exclude_ports = set(global_config.get("query", {}).get("exclude_ports", []))
    if policy_decisions is None:
        policy_decisions = global_config.get("query", {}).get(
            "policy_decisions", ["blocked", "potentially_blocked"]
        )
    thresholds = global_config.get("thresholds", {})

    services = rule.get("services", [])

    # Empty list OR [{name: All Services}] = "All Services" — query all flows, no port filter.
    all_services = not services or (
        len(services) == 1
        and isinstance(services[0], dict)
        and services[0].get("name", "").lower() in ("all services", "all")
    )
    ports = [] if all_services else _resolve_ports(services, service_port_map or {}, exclude_ports)

    if not all_services and not ports:
        named = [s["name"] for s in services if isinstance(s, dict) and "name" in s]
        if named:
            return {"traffic_found": False,
                    "reason": f"Service ports not resolved: {', '.join(named)}"}
        return {"traffic_found": False, "reason": "No queryable ports in rule (ICMP/Windows services)"}

    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=lookback_days)

        tq = TrafficQuery.build(
            start_date=start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            end_date=end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            policy_decisions=policy_decisions,
            max_results=10000,
        )

        flows = pce.get_traffic_flows_async("policy-gitops-evidence", tq)

        matching_flows = []
        total_connections = 0

        for f in flows:
            flow = f.to_json() if hasattr(f, "to_json") else (f.__dict__ if hasattr(f, "__dict__") else f)
            if isinstance(flow, str):
                flow = json.loads(flow)

            service = flow.get("service", {})
            flow_port = service.get("port") if isinstance(service, dict) else None
            flow_proto = service.get("proto", "?") if isinstance(service, dict) else "?"

            # Port filter: skip flows not matching our port list.
            # All-Services rules have no port list — include every flow.
            if not all_services and flow_port not in ports:
                continue

            src = flow.get("src", {})
            dst = flow.get("dst", {})
            num = flow.get("num_connections", 1)

            total_connections += num
            src_name = src.get("workload", {}).get("hostname", src.get("ip", "?"))
            dst_name = dst.get("workload", {}).get("hostname", dst.get("ip", "?"))

            port_label = f"{flow_port}/{flow_proto}" if flow_port else f"?/{flow_proto}"
            matching_flows.append({
                "src": src_name,
                "dst": dst_name,
                "port": port_label,
                "connections": num,
                "decision": flow.get("policy_decision", "unknown"),
            })

        if total_connections < min_connections:
            scope_desc = "any port" if all_services else f"ports {ports}"
            return {
                "traffic_found": False,
                "blocked_connections": total_connections,
                "reason": (
                    f"No blocked traffic found ({scope_desc}) in last {lookback_days} days"
                    if total_connections == 0
                    else f"Only {total_connections} connection(s) — below min_connections threshold ({min_connections})"
                ),
            }

        matching_flows.sort(key=lambda x: -x["connections"])
        unique_sources = len(set(f["src"] for f in matching_flows))
        unique_dests = len(set(f["dst"] for f in matching_flows))

        return {
            "traffic_found": True,
            "blocked_connections": total_connections,
            "unique_sources": unique_sources,
            "unique_destinations": unique_dests,
            "sample_flows": matching_flows[:10],
            "verdict": _make_verdict(total_connections, thresholds, lookback_days, unique_sources),
        }

    except Exception as e:
        return {"traffic_found": False, "error": str(e)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--changed-files", required=True)
    parser.add_argument("--lookback-days", type=int, default=30)
    parser.add_argument("--diff-base", default=None,
                        help="Git ref to diff against for detecting deleted rules (e.g. origin/main)")
    parser.add_argument("--output", default="traffic-report.json")
    args = parser.parse_args()

    config = load_traffic_config(args.lookback_days)

    if not config.get("enabled", True):
        print("Traffic evidence disabled via config — skipping")
        report = {"evidence": [], "summary": {"total_rules": 0, "justified": 0, "unjustified": 0},
                  "lookback_days": config["lookback_days"], "skipped": True}
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        return

    pce = get_pce()
    if not pce:
        print("PCE not configured — skipping traffic evidence")

    # Build service name→ports map once from the repo's services/ directory.
    # Rules reference services by name ({name: mysql}); ports live in services/mysql.yaml.
    service_port_map = load_service_port_map()
    if service_port_map:
        print(f"Loaded port definitions for {len(service_port_map)} service objects")

    files = [f.strip() for f in args.changed_files.split("\n") if f.strip() and f.endswith((".yaml", ".yml"))]

    evidence = []
    for filepath in files:
        if not os.path.exists(filepath):
            continue
        rules, scope_labels = extract_rules_from_file(filepath)
        scope_cfg = get_scope_config(config, scope_labels)

        if not scope_cfg.get("enabled", True):
            continue

        for rule in rules:
            result = query_traffic_for_rule(pce, rule, scope_cfg, config, service_port_map)
            # Collect resolved ports (inline + named service lookups) for the report
            resolved_ports = _resolve_ports(
                rule.get("services", []), service_port_map, set()
            )
            evidence.append({
                "file": rule["file"],
                "ruleset_name": rule["ruleset_name"],
                "rule_name": rule["name"],
                "ports": resolved_ports,
                **(result or {"traffic_found": False, "reason": "PCE not configured"}),
            })

    # ── Deletion impact: query allowed traffic for deleted rules ─────────────
    if args.diff_base:
        for filepath in files:
            base_data = _get_base_data(filepath, args.diff_base)
            if not base_data:
                continue
            current_data: dict = {}
            if os.path.exists(filepath):
                try:
                    with open(filepath) as f:
                        current_data = yaml.safe_load(f) or {}
                except Exception:
                    pass

            deleted = _diff_rules(base_data, current_data)
            if not deleted:
                continue

            ruleset_name = base_data.get("name") or os.path.splitext(os.path.basename(filepath))[0]
            scope_labels: dict = {}
            for scope_entry in base_data.get("scopes", []):
                for item in scope_entry:
                    if isinstance(item, dict) and "label" in item:
                        lbl = item["label"]
                        if isinstance(lbl, dict):
                            scope_labels.update(lbl)
            scope_cfg = get_scope_config(config, scope_labels)

            for rule in base_data.get("rules", []):
                if not isinstance(rule, dict):
                    continue
                name = rule.get("name", "(unnamed)")
                if deleted.get(name) != "deleted":
                    continue

                rule_entry = {
                    "file": filepath,
                    "ruleset_name": ruleset_name,
                    "name": name,
                    "consumers": rule.get("consumers", []),
                    "providers": rule.get("providers", []),
                    "services": rule.get("services", []),
                    "scope_labels": scope_labels,
                }
                result = query_traffic_for_rule(
                    pce, rule_entry, scope_cfg, config, service_port_map,
                    policy_decisions=["allowed"],
                ) or {"traffic_found": False, "reason": "PCE not configured"}

                # Rename blocked_connections → allowed_connections for clarity
                if "blocked_connections" in result:
                    result = {**result, "allowed_connections": result.pop("blocked_connections")}

                resolved_ports = _resolve_ports(rule.get("services", []), service_port_map, set())
                evidence.append({
                    "file": filepath,
                    "ruleset_name": ruleset_name,
                    "rule_name": name,
                    "ports": resolved_ports,
                    "is_deletion_impact": True,
                    **result,
                })
                print(f"  Deletion impact [{name}]: "
                      f"{'%d allowed connections' % result.get('allowed_connections', 0) if result.get('traffic_found') else 'no active traffic'}")

    current_evidence = [e for e in evidence if not e.get("is_deletion_impact")]
    justified = sum(1 for e in current_evidence if e.get("traffic_found"))
    total = len(current_evidence)

    report = {
        "evidence": evidence,
        "summary": {
            "total_rules": total,
            "justified": justified,
            "unjustified": total - justified,
        },
        "lookback_days": config["lookback_days"],
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Traffic evidence: {justified}/{total} rules justified by blocked traffic")


if __name__ == "__main__":
    main()
