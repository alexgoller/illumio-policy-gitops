#!/usr/bin/env python3
"""
Stale rule detection — runs on a schedule, not in the PR pipeline.

Walks all ruleset YAML files in scopes/, queries the PCE Explorer API for
traffic matching each allow rule over the configured lookback window. Rules
with zero traffic in both directions are reported as stale.

Deny rules and disabled rules are skipped intentionally.

Output: stale-rules-report.json consumed by the GitHub Actions workflow to
open/update GitHub Issues labeled 'stale-rule'.

Usage:
  python3 stale-rules.py \
    --lookback-days 90 \
    --output stale-rules-report.json
"""

import argparse
import glob
import json
import os
import time

import yaml

try:
    from illumio import PolicyComputeEngine
    HAS_ILLUMIO = True
except ImportError:
    HAS_ILLUMIO = False


def get_pce():
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


# ---------------------------------------------------------------------------
# Label resolution helpers (replicated from traffic-evidence.py)
# ---------------------------------------------------------------------------

def _build_label_map(pce) -> dict[str, dict]:
    label_map: dict[str, dict] = {}
    try:
        resp = pce.get("/labels", params={"max_results": 50000})
        if resp.status_code == 200:
            for lbl in resp.json():
                label_map[lbl.get("href", "")] = {
                    "key": lbl.get("key", ""),
                    "value": lbl.get("value", ""),
                    "href": lbl.get("href", ""),
                }
    except Exception as e:
        print(f"Warning: failed to fetch labels: {e}")
    return label_map


def _resolve_label_hrefs(label_kvs: list[dict], label_map: dict) -> list[str]:
    """Convert [{key: value}] actor labels to PCE label hrefs."""
    hrefs = []
    for lbl in label_kvs:
        if isinstance(lbl, dict):
            for k, v in lbl.items():
                for href, info in label_map.items():
                    if info["key"] == k and info["value"] == str(v):
                        hrefs.append(href)
    return hrefs


def _actor_label_hrefs(actors: list, label_map: dict) -> list[str]:
    """Extract all label hrefs referenced by a consumer/provider list."""
    hrefs = []
    for actor in actors:
        if isinstance(actor, dict) and "label" in actor:
            lbl = actor["label"]
            if isinstance(lbl, dict):
                hrefs.extend(_resolve_label_hrefs([lbl], label_map))
    return hrefs


# ---------------------------------------------------------------------------
# Traffic query
# ---------------------------------------------------------------------------

def query_traffic(pce, src_labels: list[str], dst_labels: list[str],
                  services: list, lookback_hours: int) -> int:
    """
    Query PCE Explorer for connection count matching the given constraints.
    Returns total connections across blocked + allowed + potentially_blocked.
    """
    src = [{"label": {"href": h}} for h in src_labels] if src_labels else [{"actors": "ams"}]
    dst = [{"label": {"href": h}} for h in dst_labels] if dst_labels else [{"actors": "ams"}]

    svc_part = []
    for s in services:
        if isinstance(s, dict):
            if "port" in s:
                entry: dict = {"port": s["port"], "proto": 6 if s.get("proto", "tcp") == "tcp" else 17}
                if "to_port" in s:
                    entry["to_port"] = s["to_port"]
                svc_part.append(entry)

    query = {
        "sources": {"include": [src], "exclude": []},
        "destinations": {"include": [dst], "exclude": []},
        "services": {"include": svc_part, "exclude": []},
        "policy_decisions": ["allowed", "blocked", "potentially_blocked"],
        "start_date": f"-{lookback_hours}h",
        "max_results": 1,
    }

    try:
        resp = pce.post("/traffic_flows/async_queries", json=query)
        if resp.status_code not in (200, 201):
            return -1
        query_href = resp.json().get("href", "")

        for _ in range(30):
            time.sleep(3)
            status_resp = pce.get(query_href)
            if status_resp.status_code != 200:
                break
            status = status_resp.json()
            if status.get("status") == "completed":
                results_href = status.get("result", {}).get("href", "")
                if not results_href:
                    return 0
                result_resp = pce.get(results_href)
                if result_resp.status_code == 200:
                    flows = result_resp.json()
                    return sum(f.get("num_connections", 1) for f in flows)
                return 0
            if status.get("status") == "failed":
                return -1
    except Exception as e:
        print(f"  Warning: traffic query failed: {e}")
        return -1

    return -1


# ---------------------------------------------------------------------------
# Rule extraction
# ---------------------------------------------------------------------------

def _fmt_services(services: list) -> str:
    if not services:
        return "All Services"
    parts = []
    for s in services:
        if not isinstance(s, dict):
            parts.append(str(s))
        elif "name" in s:
            parts.append(s["name"])
        elif "port" in s:
            proto = s.get("proto", "tcp")
            to_port = s.get("to_port")
            parts.append(f"{s['port']}-{to_port}/{proto}" if to_port else f"{s['port']}/{proto}")
    return ", ".join(parts) if parts else "All Services"


def collect_rules(scopes_root: str = "scopes") -> list[dict]:
    """Walk all YAML files under scopes/ and return allow rules."""
    rules = []
    for filepath in sorted(glob.glob(f"{scopes_root}/**/*.yaml", recursive=True)):
        if os.path.basename(filepath) == "_scope.yaml":
            continue
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            continue

        ruleset_name = data.get("name") or os.path.splitext(os.path.basename(filepath))[0]
        scope_constraints = []
        for scope_entry in data.get("scopes", []):
            if not isinstance(scope_entry, list):
                continue
            for item in scope_entry:
                if isinstance(item, dict) and "label" in item and not item.get("exclusion"):
                    lbl = item["label"]
                    if isinstance(lbl, dict):
                        scope_constraints.append(lbl)

        for rule in data.get("rules", []):
            if not isinstance(rule, dict):
                continue
            if not rule.get("enabled", True):
                continue  # disabled rules are expected to have no traffic

            rules.append({
                "file": filepath,
                "ruleset_name": ruleset_name,
                "rule_name": rule.get("name", "(unnamed)"),
                "consumers": rule.get("consumers", []),
                "providers": rule.get("providers", []),
                "services": rule.get("services", []),
                "unscoped_consumers": rule.get("unscoped_consumers", False),
                "scope_constraints": scope_constraints,
            })

    return rules


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lookback-days", type=int, default=90)
    parser.add_argument("--output", default="stale-rules-report.json")
    args = parser.parse_args()

    lookback_hours = args.lookback_days * 24

    pce = get_pce()
    if not pce:
        print("PCE not configured — cannot run stale rule detection")
        with open(args.output, "w") as f:
            json.dump({"skipped": True, "reason": "PCE not configured", "stale_rules": []}, f)
        return

    label_map = _build_label_map(pce)
    print(f"Loaded {len(label_map)} labels from PCE")

    rules = collect_rules()
    print(f"Found {len(rules)} enabled allow rules across all scope files")

    stale = []
    checked = 0

    for rule in rules:
        rule_name = rule["rule_name"]
        filepath = rule["file"]

        # Skip rules with All Services or actors:ams — too broad to query efficiently
        has_ams = any(a.get("actors") == "ams" for a in rule["consumers"] + rule["providers"])
        has_all_svc = not rule["services"]
        if has_ams or has_all_svc:
            continue

        # Resolve label hrefs
        scope_hrefs = _resolve_label_hrefs(rule["scope_constraints"], label_map)
        con_hrefs = _actor_label_hrefs(rule["consumers"], label_map)
        pro_hrefs = _actor_label_hrefs(rule["providers"], label_map)

        if not con_hrefs and not rule["unscoped_consumers"]:
            con_hrefs = scope_hrefs
        if not pro_hrefs:
            pro_hrefs = scope_hrefs

        if not con_hrefs and not pro_hrefs:
            continue  # can't form a meaningful query

        print(f"  Checking: {filepath} / {rule_name}")
        connections = query_traffic(pce, con_hrefs, pro_hrefs, rule["services"], lookback_hours)
        checked += 1

        if connections == 0:
            print(f"    → STALE (0 connections in {args.lookback_days} days)")
            stale.append({
                "file": filepath,
                "ruleset_name": rule["ruleset_name"],
                "rule_name": rule_name,
                "services": _fmt_services(rule["services"]),
                "lookback_days": args.lookback_days,
            })
        elif connections > 0:
            print(f"    → active ({connections:,} connections)")
        else:
            print(f"    → query error — skipping")

    print(f"\nStale rule detection: {len(stale)} stale out of {checked} checked")

    with open(args.output, "w") as f:
        json.dump({
            "skipped": False,
            "lookback_days": args.lookback_days,
            "rules_checked": checked,
            "stale_count": len(stale),
            "stale_rules": stale,
        }, f, indent=2)


if __name__ == "__main__":
    main()
