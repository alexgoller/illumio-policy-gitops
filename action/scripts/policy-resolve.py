#!/usr/bin/env python3
"""
Policy resolver for Illumio policy PRs.

Resolves label-based consumers and providers in changed rule files into
concrete IP addresses using live PCE workload data.  The result is written
to policy-resolution.json so render-report.py can surface it in the PR
comment under a collapsible "Resolved Policy (IP view)" section.

Usage:
  python3 policy-resolve.py \
    --changed-files "scopes/foo/bar.yaml\nip-lists/baz.yaml" \
    --output policy-resolution.json
"""

import argparse
import json
import os
from collections import defaultdict

import yaml

try:
    from illumio import PolicyComputeEngine
    HAS_ILLUMIO = True
except ImportError:
    HAS_ILLUMIO = False


# ---------------------------------------------------------------------------
# PCE connection
# ---------------------------------------------------------------------------

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
# PCE data fetch
# ---------------------------------------------------------------------------

def fetch_workloads(pce) -> list[dict]:
    """Fetch workloads and return as [{hostname, labels: {key: value}, ips: [...]}]."""
    try:
        resp = pce.get("/workloads", params={"max_results": 10000, "representation": "workload_labels"})
        raw = resp.json() if resp.status_code == 200 else []
    except Exception as e:
        print(f"Warning: failed to fetch workloads: {e}")
        return []

    # Also fetch labels to resolve hrefs → key/value
    label_map = {}
    try:
        resp = pce.get("/labels")
        if resp.status_code == 200:
            for lbl in resp.json():
                label_map[lbl.get("href", "")] = {
                    "key": lbl.get("key", ""),
                    "value": lbl.get("value", ""),
                }
    except Exception as e:
        print(f"Warning: failed to fetch labels: {e}")

    workloads = []
    for wl in raw:
        # Resolve label hrefs to key-value pairs
        labels = {}
        for lbl_ref in wl.get("labels", []):
            href = lbl_ref.get("href", "")
            if href in label_map:
                lbl = label_map[href]
                labels[lbl["key"]] = lbl["value"]
            elif "key" in lbl_ref and "value" in lbl_ref:
                # workload_labels representation already has key/value inline
                labels[lbl_ref["key"]] = lbl_ref["value"]

        ips = [
            iface.get("address", "")
            for iface in wl.get("interfaces", [])
            if iface.get("address")
        ]
        workloads.append({
            "hostname": wl.get("name") or wl.get("hostname", ""),
            "href": wl.get("href", ""),
            "labels": labels,
            "ips": ips,
        })

    print(f"Loaded {len(workloads)} workloads from PCE")
    return workloads


# ---------------------------------------------------------------------------
# Actor resolution
# ---------------------------------------------------------------------------

def _workloads_matching(workloads: list[dict], constraints: list[dict]) -> list[dict]:
    """
    Return workloads that satisfy all label constraints (AND logic).
    Each constraint is a {key: value} dict.
    Empty constraints → return all workloads.
    """
    if not constraints:
        return list(workloads)

    result = []
    for wl in workloads:
        wl_labels = wl.get("labels", {})
        if all(wl_labels.get(k) == v for c in constraints for k, v in c.items()):
            result.append(wl)
    return result


def resolve_actors(actors: list, scope_constraints: list, workloads: list[dict]) -> dict:
    """
    Resolve consumers/providers list from YAML to IP addresses.

    Actor formats (from plugin export):
      {actors: ams}           → all workloads in scope
      {label: {role: dc}}     → workloads with that label, intersected with scope
      {ip_list: {name: "..."}} → IP list reference (not resolvable to IPs here)

    scope_constraints: [{key: value}] from the ruleset's scopes field.
    """
    label_constraints = []
    ip_list_names = []
    is_ams = False

    for actor in actors:
        if not isinstance(actor, dict):
            continue
        if actor.get("actors") == "ams":
            is_ams = True
        elif "label" in actor:
            lbl = actor["label"]
            if isinstance(lbl, dict):
                label_constraints.append(dict(lbl))
        elif "ip_list" in actor:
            ipl = actor["ip_list"]
            if isinstance(ipl, dict):
                ip_list_names.append(ipl.get("name", str(ipl)))
            else:
                ip_list_names.append(str(ipl))

    if is_ams:
        # All workloads within scope (no additional label filtering)
        constraints = list(scope_constraints)
        label_desc = "All Workloads (in scope)"
    else:
        # Scope + rule-level label constraints (AND)
        constraints = list(scope_constraints) + label_constraints
        label_desc = " AND ".join(
            f"{k}={v}" for c in constraints for k, v in c.items()
        ) or "(none)"

    matching = _workloads_matching(workloads, constraints)

    hostnames = [wl["hostname"] for wl in matching if wl["hostname"]]
    ips = []
    for wl in matching:
        ips.extend(wl["ips"])

    return {
        "label_desc": label_desc,
        "hostnames": sorted(set(hostnames)),
        "ips": sorted(set(ips)),
        "workload_count": len(matching),
        "ip_lists": ip_list_names,
    }


# ---------------------------------------------------------------------------
# Rule extraction
# ---------------------------------------------------------------------------

def _scope_constraints(scopes: list) -> list[dict]:
    """Extract label constraints from a ruleset's scopes field."""
    constraints = []
    for scope_entry in scopes:
        if not isinstance(scope_entry, list):
            continue
        for item in scope_entry:
            if isinstance(item, dict) and "label" in item:
                lbl = item["label"]
                if isinstance(lbl, dict) and not item.get("exclusion"):
                    constraints.append(dict(lbl))
    return constraints


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


def extract_rules_from_file(filepath: str) -> tuple[list, list]:
    """Return (rules_list, scope_constraints) from a YAML policy file."""
    try:
        with open(filepath) as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return [], []

    scope_constraints = _scope_constraints(data.get("scopes", []))
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
                "unscoped_consumers": rule.get("unscoped_consumers", False),
                "scope_constraints": scope_constraints,
            })

    return rules, scope_constraints


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--changed-files", required=True)
    parser.add_argument("--output", default="policy-resolution.json")
    args = parser.parse_args()

    pce = get_pce()
    if not pce:
        print("PCE not configured — skipping policy resolution")
        with open(args.output, "w") as f:
            json.dump({"resolutions": [], "skipped": True, "reason": "PCE not configured"}, f, indent=2)
        return

    workloads = fetch_workloads(pce)
    if not workloads:
        print("No workloads fetched — skipping policy resolution")
        with open(args.output, "w") as f:
            json.dump({"resolutions": [], "skipped": True, "reason": "No workloads from PCE"}, f, indent=2)
        return

    files = [
        f.strip() for f in args.changed_files.split("\n")
        if f.strip() and f.endswith((".yaml", ".yml"))
    ]

    resolutions = []
    for filepath in files:
        if not os.path.exists(filepath):
            continue
        # Skip non-scope files (IP lists / services don't have rules to resolve)
        if not filepath.startswith("scopes/"):
            continue

        rules, scope_constraints = extract_rules_from_file(filepath)
        for rule in rules:
            sc = rule["scope_constraints"]
            consumer_scope = [] if rule.get("unscoped_consumers") else sc
            consumers = resolve_actors(rule["consumers"], consumer_scope, workloads)
            providers = resolve_actors(rule["providers"], sc, workloads)

            resolutions.append({
                "file": filepath,
                "ruleset_name": rule["ruleset_name"],
                "rule_name": rule["name"],
                "services": _fmt_services(rule.get("services", [])),
                "consumers": consumers,
                "providers": providers,
            })

    total_workloads = len(workloads)
    print(f"Policy resolution: {len(resolutions)} rules resolved using {total_workloads} workloads")

    with open(args.output, "w") as f:
        json.dump({
            "resolutions": resolutions,
            "total_workloads": total_workloads,
        }, f, indent=2)


if __name__ == "__main__":
    main()
