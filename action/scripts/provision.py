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
    """Build lookup caches for labels, services, and IP lists."""
    labels = pce.get("/labels").json()
    label_map = {}
    for lbl in labels:
        label_map[(lbl["key"], lbl["value"])] = lbl["href"]

    services = pce.get("/sec_policy/active/services").json()
    svc_map = {s["name"]: s["href"] for s in services}

    ip_lists = pce.get("/sec_policy/active/ip_lists").json()
    ipl_map = {ipl["name"]: ipl["href"] for ipl in ip_lists}

    return label_map, svc_map, ipl_map


def resolve_label(lbl_dict, label_map):
    for key, value in lbl_dict.items():
        href = label_map.get((key, value))
        if href:
            return {"label": {"href": href}}
    return None


def resolve_actor(actor, label_map, ipl_map=None):
    if isinstance(actor, dict):
        if "actors" in actor:
            return actor
        if "label" in actor:
            return resolve_label(actor["label"], label_map)
        if "ip_list" in actor:
            ipl = actor["ip_list"]
            if isinstance(ipl, dict):
                if "href" in ipl:
                    return {"ip_list": {"href": ipl["href"]}}
                if "name" in ipl and ipl_map:
                    href = ipl_map.get(ipl["name"])
                    if href:
                        return {"ip_list": {"href": href}}
                    print(f"    Warning: IP list '{ipl['name']}' not found in PCE — skipping actor")
                    return None
    return actor


def resolve_service(svc, svc_map):
    if isinstance(svc, dict):
        if "name" in svc and svc["name"] in svc_map:
            return {"href": svc_map[svc["name"]]}
        if "port" in svc:
            proto_map = {"tcp": 6, "udp": 17}
            return {"port": svc["port"], "proto": proto_map.get(svc.get("proto", "tcp"), 6)}
    return svc


def dedup_services(services: list) -> list:
    """Remove duplicate service entries before sending to PCE.

    Two entries are considered duplicates when they share the same href
    (named service) or the same port+proto pair (inline port).  The PCE
    rejects rules with duplicate service references with HTTP 406.
    """
    seen = set()
    result = []
    for svc in services:
        if not isinstance(svc, dict):
            result.append(svc)
            continue
        key = svc.get("href") or (svc.get("port"), svc.get("proto"))
        if key not in seen:
            seen.add(key)
            result.append(svc)
        else:
            print(f"    Warning: duplicate service reference removed: {svc}")
    return result


def provision_ip_list(pce, filepath, data, label_map, ipl_map=None):
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


def provision_service(pce, filepath, data):
    """Create or update a named service on the PCE draft (Git -> PCE).

    Net-new services authored in Git must be created so that rules referencing
    them by name resolve. Matches an existing draft service by name.
    """
    name = data["name"]
    proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
    service_ports = []
    for sp in data.get("service_ports", []):
        if not isinstance(sp, dict):
            continue
        entry = {}
        if "port" in sp:
            entry["port"] = sp["port"]
        if "to_port" in sp:
            entry["to_port"] = sp["to_port"]
        proto = sp.get("proto", "tcp")
        entry["proto"] = proto_map.get(proto, proto) if isinstance(proto, str) else proto
        service_ports.append(entry)

    body = {
        "name": name,
        "description": data.get("description") or "",
        "service_ports": service_ports,
    }
    existing = pce.get("/sec_policy/draft/services").json()
    found = next((s for s in existing if s["name"] == name), None)
    if found:
        pce.put(found["href"], json=body)
        return "updated", name
    else:
        pce.post("/sec_policy/draft/services", json=body)
        return "created", name


def _refresh_service_cache(pce, svc_map):
    """Merge current draft services into svc_map so rules resolve newly-created services."""
    for s in pce.get("/sec_policy/draft/services").json():
        svc_map[s["name"]] = s["href"]


def provision_ruleset(pce, filepath, data, label_map, svc_map, ipl_map=None):
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
            "providers": [a for a in (resolve_actor(a, label_map, ipl_map) for a in rule.get("providers", [])) if a],
            "consumers": [a for a in (resolve_actor(a, label_map, ipl_map) for a in rule.get("consumers", [])) if a],
            "ingress_services": dedup_services([resolve_service(s, svc_map) for s in rule.get("services", [])]),
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

    elif filepath.startswith("services/"):
        existing = pce.get("/sec_policy/draft/services").json()
        for s in existing:
            sanitized = s["name"].lower().replace(" ", "-").replace("/", "-")
            if sanitized == basename or s["name"] == basename:
                pce.delete(s["href"])
                return "deleted", s["name"]

    elif filepath.startswith("scopes/"):
        existing = pce.get("/sec_policy/draft/rule_sets", params={"max_results": 5000}).json()
        for rs in existing:
            sanitized = rs["name"].lower().replace(" ", "-").replace("|", "-").replace("/", "-")
            if basename in sanitized or rs["name"] == basename:
                pce.delete(rs["href"])
                return "deleted", rs["name"]

    return "skip", basename


def provision_to_active(pce, description: str):
    """Promote all pending PCE draft changes to active policy."""
    resp = pce.post("/sec_policy", json={"update_description": description})
    if resp.status_code in (200, 201):
        job = resp.json()
        href = job.get("href", "")
        print(f"Provisioned draft to active (job: {href})")
        return True
    print(f"WARNING: provision to active failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return False


def write_report(report: dict, path: str = "provision-report.json"):
    import json
    with open(path, "w") as f:
        json.dump(report, f, indent=2)


def main():
    changed_raw = os.environ.get("CHANGED_FILES", "")
    if not changed_raw.strip():
        print("No changed files")
        write_report({"status": "skipped", "created": 0, "updated": 0, "deleted": 0,
                      "errors": [], "provisioned_to_active": False, "files": []})
        return

    pce = get_pce()
    label_map, svc_map, ipl_map = build_caches(pce)

    files = [f.strip() for f in changed_raw.split("\n") if f.strip()]

    # Provision dependencies before dependents: ip-lists and services must exist
    # before the rulesets that reference them by name can resolve.
    def _order(fp):
        if fp.startswith("ip-lists/"):
            return 0
        if fp.startswith("services/"):
            return 1
        if fp.startswith("scopes/"):
            return 2
        return 3
    files.sort(key=_order)
    print(f"Processing {len(files)} changed files...")

    created = 0
    updated = 0
    deleted = 0
    errors = []
    processed_files = []
    services_dirty = False  # a service was created/updated this run
    cache_refreshed = False  # svc_map refreshed before scopes are processed

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
                    processed_files.append({"file": filepath, "action": "deleted", "name": name})
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

        # Generated courtesy/doc files are derived from canonical policy — skip them.
        if data.get("generated"):
            continue

        try:
            if filepath.startswith("ip-lists/"):
                action, name = provision_ip_list(pce, filepath, data, label_map, ipl_map)
            elif filepath.startswith("services/"):
                action, name = provision_service(pce, filepath, data)
                if action in ("created", "updated"):
                    services_dirty = True
            elif filepath.startswith("scopes/"):
                if "rules" not in data:
                    continue
                # Pick up services created earlier this run before resolving the ruleset.
                if services_dirty and not cache_refreshed:
                    _refresh_service_cache(pce, svc_map)
                    cache_refreshed = True
                action, name = provision_ruleset(pce, filepath, data, label_map, svc_map, ipl_map)
            else:
                continue

            if action == "created":
                created += 1
            elif action == "updated":
                updated += 1
            processed_files.append({"file": filepath, "action": action, "name": name})
            print(f"  {action.title()}: {name}")

        except Exception as e:
            errors.append(f"{filepath}: {e}")

    total_changes = created + updated + deleted
    print(f"\nResult: {created} created, {updated} updated, {deleted} deleted, {len(errors)} errors")

    if errors:
        for e in errors:
            print(f"  ERROR: {e}")
        write_report({
            "status": "error",
            "created": created,
            "updated": updated,
            "deleted": deleted,
            "errors": errors,
            "provisioned_to_active": False,
            "files": processed_files,
        })
        sys.exit(1)

    # Promote draft to active unless explicitly disabled.
    # AUTO_PROVISION defaults to true — the script runs on merge, which implies approval.
    auto_provision = os.environ.get("AUTO_PROVISION", "true").lower() not in ("false", "0", "no")
    provisioned = False
    if auto_provision and total_changes > 0:
        print("\nProvisioning draft to active...")
        commit_msg = os.environ.get("PROVISION_DESCRIPTION",
                                    f"GitOps: {created} created, {updated} updated, {deleted} deleted")
        provisioned = provision_to_active(pce, commit_msg)
        if not provisioned:
            write_report({
                "status": "error",
                "created": created,
                "updated": updated,
                "deleted": deleted,
                "errors": ["provision_to_active failed — see logs"],
                "provisioned_to_active": False,
                "files": processed_files,
            })
            sys.exit(1)
    elif not auto_provision:
        print("\nAUTO_PROVISION=false — draft changes left pending for manual review")

    write_report({
        "status": "success",
        "created": created,
        "updated": updated,
        "deleted": deleted,
        "errors": [],
        "provisioned_to_active": provisioned,
        "auto_provision": auto_provision,
        "files": processed_files,
    })


if __name__ == "__main__":
    main()
