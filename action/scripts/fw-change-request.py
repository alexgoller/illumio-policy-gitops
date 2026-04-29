#!/usr/bin/env python3
"""
Generate firewall change request files from resolved policy.

Reads policy-resolution.json (produced by policy-resolve.py) and the
changed YAML files, then writes:

  fw-changes/fw-change-request.csv  — flat (src, dst, port, proto) table
                                       suitable for AlgoSec / Tufin / FireMon import
  fw-changes/fw-change-request.json — structured format for API-driven automation

Each CSV row is one firewall tuple: source_ip × destination_ip × port × protocol.
Rules with "All Services" get port=any / protocol=any.
Change type (added/deleted/modified/unchanged) is carried from the git diff.

Usage:
  python3 fw-change-request.py \\
    --resolution policy-resolution.json \\
    --changed-files "scopes/foo/bar.yaml" \\
    --diff-base origin/main \\
    --commit abc1234 \\
    --pr-title "feat: update AD ruleset" \\
    --out-dir fw-changes
"""

import argparse
import csv
import json
import os
import subprocess
from collections import defaultdict
from datetime import datetime, timezone

import yaml

PROTO_NUM = {6: "tcp", 17: "udp", 1: "icmp"}


# ---------------------------------------------------------------------------
# Service port resolution
# ---------------------------------------------------------------------------

def load_service_port_map(repo_root: str = ".") -> dict[str, list[dict]]:
    """Build name → [{port, proto}] from services/*.yaml."""
    svc_dir = os.path.join(repo_root, "services")
    port_map: dict[str, list[dict]] = {}
    if not os.path.isdir(svc_dir):
        return port_map
    for fname in os.listdir(svc_dir):
        if not fname.endswith((".yaml", ".yml")):
            continue
        try:
            with open(os.path.join(svc_dir, fname)) as f:
                data = yaml.safe_load(f) or {}
            name = data.get("name", "")
            ports = []
            for sp in data.get("service_ports", []):
                if not isinstance(sp, dict):
                    continue
                port = sp.get("port")
                proto_raw = sp.get("proto", 6)
                proto = PROTO_NUM.get(proto_raw, str(proto_raw)) if isinstance(proto_raw, int) else proto_raw
                if port is not None:
                    ports.append({"port": port, "proto": proto})
            if name and ports:
                port_map[name] = ports
        except Exception:
            pass
    return port_map


def resolve_services(services_list: list, port_map: dict) -> list[dict]:
    """
    Resolve a rule's services list to [{port, proto}].
    Returns [{"port": "any", "proto": "any"}] for All Services.
    """
    if not services_list:
        return [{"port": "any", "proto": "any"}]

    # Single entry that is the "All Services" pseudo-object
    if (len(services_list) == 1
            and isinstance(services_list[0], dict)
            and services_list[0].get("name", "").lower() in ("all services", "all")):
        return [{"port": "any", "proto": "any"}]

    resolved = []
    for svc in services_list:
        if not isinstance(svc, dict):
            continue
        if "port" in svc:
            proto_raw = svc.get("proto", "tcp")
            proto = PROTO_NUM.get(proto_raw, str(proto_raw)) if isinstance(proto_raw, int) else proto_raw
            resolved.append({"port": svc["port"], "proto": proto})
        elif "name" in svc:
            name = svc["name"]
            if name.lower() in ("all services", "all"):
                return [{"port": "any", "proto": "any"}]
            for entry in port_map.get(name, []):
                resolved.append(dict(entry))
            if name not in port_map:
                # Named service not in local map — preserve as opaque name
                resolved.append({"port": "?", "proto": "?", "service_name": name})
    return resolved or [{"port": "any", "proto": "any"}]


# ---------------------------------------------------------------------------
# Git diff helpers (same pattern as render-report.py)
# ---------------------------------------------------------------------------

def _get_base_data(filepath: str, diff_base: str) -> dict | None:
    try:
        raw = subprocess.check_output(
            ["git", "show", f"{diff_base}:{filepath}"],
            stderr=subprocess.DEVNULL,
        )
        return yaml.safe_load(raw) or {}
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _rule_fingerprint(rule: dict) -> str:
    def _sort(obj):
        if isinstance(obj, dict):
            return {k: _sort(v) for k, v in sorted(obj.items())}
        if isinstance(obj, list):
            return [_sort(x) for x in obj]
        return obj
    return json.dumps(_sort(rule), sort_keys=True)


def _rules_by_name(data: dict) -> dict[str, dict]:
    result = {}
    for rule in data.get("rules", []):
        if isinstance(rule, dict):
            result[rule.get("name", "(unnamed)")] = rule
    return result


def diff_rules(base_data: dict | None, current_data: dict) -> dict[str, str]:
    """Return {rule_name: change_type} where change_type ∈ added/deleted/modified/unchanged."""
    current = _rules_by_name(current_data)
    if base_data is None:
        return {n: "added" for n in current}
    base = _rules_by_name(base_data)
    status = {}
    for name in set(base) | set(current):
        if name not in base:
            status[name] = "added"
        elif name not in current:
            status[name] = "deleted"
        elif _rule_fingerprint(base[name]) != _rule_fingerprint(current[name]):
            status[name] = "modified"
        else:
            status[name] = "unchanged"
    return status


# ---------------------------------------------------------------------------
# Core: explode rule into firewall tuples
# ---------------------------------------------------------------------------

def explode_rule(entry: dict, change_type: str, services: list[dict]) -> list[dict]:
    """
    Cross-product of source IPs × destination IPs × services.
    Falls back to label descriptions when IPs are not resolved.
    """
    cons = entry.get("consumers", {})
    provs = entry.get("providers", {})

    src_ips = cons.get("ips") or []
    dst_ips = provs.get("ips") or []

    # Fall back to IP list names or label description if no IPs resolved
    if not src_ips:
        ip_lists = cons.get("ip_lists", [])
        src_ips = [f"IP-List:{n}" for n in ip_lists] if ip_lists else [cons.get("label_desc", "?")]
    if not dst_ips:
        ip_lists = provs.get("ip_lists", [])
        dst_ips = [f"IP-List:{n}" for n in ip_lists] if ip_lists else [provs.get("label_desc", "?")]

    tuples = []
    for src in src_ips:
        for dst in dst_ips:
            for svc in services:
                tuples.append({
                    "change_type": change_type,
                    "action": "allow",
                    "rule_name": entry["rule_name"],
                    "ruleset": entry.get("ruleset_name", ""),
                    "file": entry["file"],
                    "source_ip": src,
                    "destination_ip": dst,
                    "port": svc["port"],
                    "protocol": svc["proto"],
                    "service_name": svc.get("service_name", ""),
                })
    return tuples


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolution", default="policy-resolution.json")
    parser.add_argument("--changed-files", required=True)
    parser.add_argument("--diff-base", default=None)
    parser.add_argument("--commit", default="")
    parser.add_argument("--pr-title", default="")
    parser.add_argument("--out-dir", default="fw-changes")
    args = parser.parse_args()

    try:
        with open(args.resolution) as f:
            resolution = json.load(f)
    except Exception as e:
        print(f"Could not read resolution file: {e} — skipping fw-change-request")
        return

    if resolution.get("skipped"):
        print("Policy resolution was skipped — no fw-change-request generated")
        return

    port_map = load_service_port_map()
    if port_map:
        print(f"Loaded port definitions for {len(port_map)} service objects")

    changed_files = [
        f.strip() for f in args.changed_files.split("\n")
        if f.strip() and f.endswith((".yaml", ".yml"))
    ]

    # Build per-file rule data and diff status
    rule_services: dict[tuple, list[dict]] = {}  # (file, rule_name) → [{port, proto}]
    rule_diff: dict[tuple, str] = {}             # (file, rule_name) → change_type

    for filepath in changed_files:
        if not filepath.startswith("scopes/"):
            continue

        current_data: dict = {}
        if os.path.exists(filepath):
            try:
                with open(filepath) as f:
                    current_data = yaml.safe_load(f) or {}
            except Exception:
                pass

        # Diff
        base_data = None
        if args.diff_base:
            base_data = _get_base_data(filepath, args.diff_base)
        file_diff = diff_rules(base_data, current_data)

        # Deleted rules: get service info from base
        if base_data:
            for rule in base_data.get("rules", []):
                if not isinstance(rule, dict):
                    continue
                name = rule.get("name", "(unnamed)")
                if file_diff.get(name) == "deleted":
                    svcs = resolve_services(rule.get("services", []), port_map)
                    rule_services[(filepath, name)] = svcs
                    rule_diff[(filepath, name)] = "deleted"

        # Current rules
        for rule in current_data.get("rules", []):
            if not isinstance(rule, dict):
                continue
            name = rule.get("name", "(unnamed)")
            svcs = resolve_services(rule.get("services", []), port_map)
            rule_services[(filepath, name)] = svcs
            rule_diff[(filepath, name)] = file_diff.get(name, "unchanged")

    # Build firewall tuples from resolution entries
    all_tuples = []
    all_rules_structured = []

    for entry in resolution.get("resolutions", []):
        key = (entry["file"], entry["rule_name"])
        change_type = rule_diff.get(key, "unchanged")
        services = rule_services.get(key, [{"port": "any", "proto": "any"}])

        tuples = explode_rule(entry, change_type, services)
        all_tuples.extend(tuples)

        all_rules_structured.append({
            "change_type": change_type,
            "action": "allow",
            "rule_name": entry["rule_name"],
            "ruleset": entry.get("ruleset_name", ""),
            "file": entry["file"],
            "consumers": entry.get("consumers", {}),
            "providers": entry.get("providers", {}),
            "services": services,
            "firewall_rules": tuples,
        })

    os.makedirs(args.out_dir, exist_ok=True)

    fieldnames = [
        "change_type", "action", "rule_name", "ruleset", "file",
        "source_ip", "destination_ip", "port", "protocol", "service_name",
    ]
    generated_at = datetime.now(timezone.utc).isoformat()

    added   = sum(1 for r in all_rules_structured if r["change_type"] == "added")
    deleted = sum(1 for r in all_rules_structured if r["change_type"] == "deleted")
    modified = sum(1 for r in all_rules_structured if r["change_type"] == "modified")

    # ── Per-scope files (mirroring directory structure) ───────────────────────
    tuples_by_file: dict[str, list] = defaultdict(list)
    rules_by_file: dict[str, list] = defaultdict(list)
    for t in all_tuples:
        tuples_by_file[t["file"]].append(t)
    for r in all_rules_structured:
        rules_by_file[r["file"]].append(r)

    for filepath, tuples in tuples_by_file.items():
        base = os.path.splitext(filepath)[0]          # scopes/app-ad_env-prod/ad-prod
        scope_out = os.path.join(args.out_dir, base)  # fw-changes/scopes/app-ad_env-prod/ad-prod
        os.makedirs(os.path.dirname(scope_out), exist_ok=True)

        with open(scope_out + ".csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(tuples)

        scope_rules = rules_by_file[filepath]
        s_added    = sum(1 for r in scope_rules if r["change_type"] == "added")
        s_deleted  = sum(1 for r in scope_rules if r["change_type"] == "deleted")
        s_modified = sum(1 for r in scope_rules if r["change_type"] == "modified")
        with open(scope_out + ".json", "w") as f:
            json.dump({
                "generated_at": generated_at,
                "commit": args.commit,
                "pr_title": args.pr_title,
                "scope_file": filepath,
                "summary": {
                    "total_rules": len(scope_rules),
                    "added": s_added,
                    "deleted": s_deleted,
                    "modified": s_modified,
                    "total_fw_tuples": len(tuples),
                },
                "rules": scope_rules,
            }, f, indent=2)

        print(f"  {scope_out}.csv  ({len(tuples)} tuples, {s_added}+ {s_deleted}- {s_modified}~)")

    # ── Combined files (full PR overview) ─────────────────────────────────────
    csv_path  = os.path.join(args.out_dir, "fw-change-request.csv")
    json_path = os.path.join(args.out_dir, "fw-change-request.json")

    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_tuples)

    with open(json_path, "w") as f:
        json.dump({
            "generated_at": generated_at,
            "commit": args.commit,
            "pr_title": args.pr_title,
            "summary": {
                "total_rules": len(all_rules_structured),
                "added": added,
                "deleted": deleted,
                "modified": modified,
                "total_fw_tuples": len(all_tuples),
            },
            "rules": all_rules_structured,
        }, f, indent=2)

    print(
        f"Firewall change request: {len(all_tuples)} tuples from {len(all_rules_structured)} rules "
        f"({added} added, {deleted} deleted, {modified} modified)"
    )
    print(f"  Combined CSV:  {csv_path}")
    print(f"  Combined JSON: {json_path}")


if __name__ == "__main__":
    main()
