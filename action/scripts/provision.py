#!/usr/bin/env python3
"""
Provision changed YAML policy files to PCE draft.

Reads changed files from CHANGED_FILES env var, parses YAML,
resolves labels/services to PCE hrefs, and creates/updates
rulesets and IP lists on the PCE draft policy.

Also handles DELETIONS: if a YAML file was removed in the commit,
the corresponding PCE object is deleted from draft.
"""

import os
import sys

import yaml
from illumio import PolicyComputeEngine


def get_pce():
    pce = PolicyComputeEngine(
        url=os.environ["PCE_HOST"],
        port=os.environ.get("PCE_PORT", "8443"),
        org_id=os.environ.get("PCE_ORG_ID", "1"),
    )
    pce.set_credentials(
        username=os.environ["PCE_API_KEY"],
        password=os.environ["PCE_API_SECRET"],
    )
    pce.set_tls_settings(verify=False)
    return pce


def build_caches(pce):
    """Build lookup caches for labels and services."""
    labels = pce.get("/labels").json()
    label_map = {}
    for lbl in labels:
        label_map[(lbl["key"], lbl["value"])] = lbl["href"]

    services = pce.get("/sec_policy/active/services").json()
    svc_map = {s["name"]: s["href"] for s in services}

    return label_map, svc_map


def resolve_label(lbl_dict, label_map):
    for key, value in lbl_dict.items():
        href = label_map.get((key, value))
        if href:
            return {"label": {"href": href}}
    return None


def resolve_actor(actor, label_map):
    if isinstance(actor, dict):
        if "actors" in actor:
            return actor
        if "label" in actor:
            return resolve_label(actor["label"], label_map)
    return actor


def resolve_service(svc, svc_map):
    if isinstance(svc, dict):
        if "name" in svc and svc["name"] in svc_map:
            return {"href": svc_map[svc["name"]]}
        if "port" in svc:
            proto_map = {"tcp": 6, "udp": 17}
            return {"port": svc["port"], "proto": proto_map.get(svc.get("proto", "tcp"), 6)}
    return svc


def provision_ip_list(pce, filepath, data, label_map):
    name = data["name"]
    body = {
        "name": name,
        "description": data.get("description") or "",
        "ip_ranges": data.get("ip_ranges", []),
        "fqdns": [{"fqdn": f} if isinstance(f, str) else f for f in data.get("fqdns", [])],
    }
    existing = pce.get("/sec_policy/draft/ip_lists").json()
    found = next((ipl for ipl in existing if ipl["name"] == name), None)
    if found:
        pce.put(found["href"], json=body)
        return "updated", name
    else:
        pce.post("/sec_policy/draft/ip_lists", json=body)
        return "created", name


def provision_ruleset(pce, filepath, data, label_map, svc_map):
    name = data["name"]

    scopes = []
    for scope_list in data.get("scopes", []):
        scope_entry = []
        for item in scope_list:
            if isinstance(item, dict) and "label" in item:
                resolved = resolve_label(item["label"], label_map)
                if resolved:
                    scope_entry.append({**resolved, "exclusion": item.get("exclusion", False)})
        scopes.append(scope_entry)

    rules = []
    for rule in data.get("rules", []):
        r = {
            "enabled": rule.get("enabled", True),
            "providers": [a for a in (resolve_actor(a, label_map) for a in rule.get("providers", [])) if a],
            "consumers": [a for a in (resolve_actor(a, label_map) for a in rule.get("consumers", [])) if a],
            "ingress_services": [resolve_service(s, svc_map) for s in rule.get("services", [])],
            "resolve_labels_as": {"providers": ["workloads"], "consumers": ["workloads"]},
        }
        if rule.get("unscoped_consumers"):
            r["unscoped_consumers"] = True
        rules.append(r)

    body = {
        "name": name,
        "description": data.get("description") or "",
        "enabled": data.get("enabled", True),
        "scopes": scopes if scopes else [[]],
        "rules": rules,
    }

    existing = pce.get("/sec_policy/draft/rule_sets", params={"max_results": 5000}).json()
    found = next((rs for rs in existing if rs["name"] == name), None)
    if found:
        pce.put(found["href"], json=body)
        return "updated", name
    else:
        pce.post("/sec_policy/draft/rule_sets", json=body)
        return "created", name


def delete_object(pce, filepath):
    """Handle deleted YAML files — remove corresponding PCE object."""
    basename = os.path.splitext(os.path.basename(filepath))[0]

    if filepath.startswith("ip-lists/"):
        existing = pce.get("/sec_policy/draft/ip_lists").json()
        for ipl in existing:
            sanitized = ipl["name"].lower().replace(" ", "-").replace("/", "-")
            if sanitized == basename or ipl["name"] == basename:
                pce.delete(ipl["href"])
                return "deleted", ipl["name"]

    elif filepath.startswith("scopes/"):
        existing = pce.get("/sec_policy/draft/rule_sets", params={"max_results": 5000}).json()
        for rs in existing:
            sanitized = rs["name"].lower().replace(" ", "-").replace("|", "-").replace("/", "-")
            if basename in sanitized or rs["name"] == basename:
                pce.delete(rs["href"])
                return "deleted", rs["name"]

    return "skip", basename


def main():
    changed_raw = os.environ.get("CHANGED_FILES", "")
    if not changed_raw.strip():
        print("No changed files")
        return

    pce = get_pce()
    label_map, svc_map = build_caches(pce)

    files = [f.strip() for f in changed_raw.split("\n") if f.strip()]
    print(f"Processing {len(files)} changed files...")

    created = 0
    updated = 0
    deleted = 0
    errors = []

    for filepath in files:
        if "_scope.yaml" in filepath or ".gitkeep" in filepath:
            continue
        if not filepath.endswith((".yaml", ".yml")):
            continue

        # File deleted = object should be removed from PCE
        if not os.path.exists(filepath):
            try:
                action, name = delete_object(pce, filepath)
                if action == "deleted":
                    deleted += 1
                    print(f"  Deleted: {name} (file removed: {filepath})")
            except Exception as e:
                errors.append(f"DELETE {filepath}: {e}")
            continue

        # File exists = create or update
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f)
        except Exception as e:
            errors.append(f"PARSE {filepath}: {e}")
            continue

        if not isinstance(data, dict) or "name" not in data:
            continue

        try:
            if filepath.startswith("ip-lists/"):
                action, name = provision_ip_list(pce, filepath, data, label_map)
            elif filepath.startswith("scopes/"):
                if "rules" not in data:
                    continue
                action, name = provision_ruleset(pce, filepath, data, label_map, svc_map)
            else:
                continue

            if action == "created":
                created += 1
            elif action == "updated":
                updated += 1
            print(f"  {action.title()}: {name}")

        except Exception as e:
            errors.append(f"{filepath}: {e}")

    print(f"\nResult: {created} created, {updated} updated, {deleted} deleted, {len(errors)} errors")
    if errors:
        for e in errors:
            print(f"  ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
