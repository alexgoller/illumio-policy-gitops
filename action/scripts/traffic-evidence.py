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
import sys
from datetime import datetime, timezone, timedelta

import yaml

try:
    from illumio import PolicyComputeEngine
    from illumio.explorer import TrafficQuery
    HAS_ILLUMIO = True
except ImportError:
    HAS_ILLUMIO = False


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

    rules = []
    for rule in data.get("rules", []):
        if isinstance(rule, dict):
            rules.append({
                "file": filepath,
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


def query_traffic_for_rule(pce, rule: dict, scope_cfg: dict, global_config: dict) -> dict:
    """Query PCE for blocked traffic matching a rule's pattern."""
    if not pce:
        return None

    lookback_days = scope_cfg.get("lookback_days", 30)
    min_connections = scope_cfg.get("min_connections", 1)
    exclude_ports = set(global_config.get("query", {}).get("exclude_ports", []))
    policy_decisions = global_config.get("query", {}).get(
        "policy_decisions", ["blocked", "potentially_blocked"]
    )
    thresholds = global_config.get("thresholds", {})

    # Extract ports
    ports = []
    for svc in rule.get("services", []):
        if isinstance(svc, dict):
            port = svc.get("port")
            if port and port not in exclude_ports:
                ports.append(port)

    if not ports:
        return {"traffic_found": False, "reason": "No specific ports in rule"}

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

            if flow_port not in ports:
                continue

            src = flow.get("src", {})
            dst = flow.get("dst", {})
            num = flow.get("num_connections", 1)

            total_connections += num
            src_name = src.get("workload", {}).get("hostname", src.get("ip", "?"))
            dst_name = dst.get("workload", {}).get("hostname", dst.get("ip", "?"))

            matching_flows.append({
                "src": src_name,
                "dst": dst_name,
                "port": f"{flow_port}/{service.get('proto', '?')}",
                "connections": num,
                "decision": flow.get("policy_decision", "unknown"),
            })

        if total_connections < min_connections:
            return {
                "traffic_found": False,
                "blocked_connections": total_connections,
                "reason": (
                    f"No blocked traffic found on ports {ports} in last {lookback_days} days"
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
            result = query_traffic_for_rule(pce, rule, scope_cfg, config)
            evidence.append({
                "file": rule["file"],
                "rule_name": rule["name"],
                "ports": [s.get("port") for s in rule.get("services", []) if isinstance(s, dict) and s.get("port")],
                **(result or {"traffic_found": False, "reason": "PCE not configured"}),
            })

    justified = sum(1 for e in evidence if e.get("traffic_found"))
    total = len(evidence)

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
