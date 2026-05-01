#!/usr/bin/env python3
"""
Label existence validation for Illumio policy PRs.

A rule referencing {role: web} when no label role=web exists in the PCE
will silently match zero workloads — it looks like real policy but does
nothing. This check catches that class of silent misconfiguration at PR time.

Exits 1 if any missing labels are found (blocks the PR).

Usage:
  python3 label-check.py \
    --changed-files "scopes/foo/bar.yaml" \
    --output label-check-report.json
"""

import argparse
import json
import os
import sys

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


def fetch_label_set(pce) -> set[tuple[str, str]]:
    try:
        resp = pce.get("/labels", params={"max_results": 50000})
        if resp.status_code == 200:
            return {(lbl.get("key", ""), lbl.get("value", "")) for lbl in resp.json()}
    except Exception as e:
        print(f"Warning: failed to fetch labels: {e}")
    return set()


def extract_label_refs(data: dict) -> list[tuple[str, str, str]]:
    """
    Walk all label references in a ruleset YAML.
    Returns [(key, value, context_description), ...].
    """
    refs = []

    # Scope constraints
    for i, scope_entry in enumerate(data.get("scopes", [])):
        if not isinstance(scope_entry, list):
            continue
        for item in scope_entry:
            if isinstance(item, dict) and "label" in item:
                lbl = item["label"]
                if isinstance(lbl, dict):
                    for k, v in lbl.items():
                        refs.append((k, str(v), f"scopes[{i}]"))

    # Allow rules + deny rules
    for rule_list, section in [
        (data.get("rules", []), "rules"),
        (data.get("deny_rules", []), "deny_rules"),
    ]:
        for rule in rule_list:
            if not isinstance(rule, dict):
                continue
            rule_name = rule.get("name", "(unnamed)")
            for field in ("consumers", "providers"):
                for actor in rule.get(field, []):
                    if isinstance(actor, dict) and "label" in actor:
                        lbl = actor["label"]
                        if isinstance(lbl, dict):
                            for k, v in lbl.items():
                                refs.append((k, str(v), f"{section}.{rule_name}.{field}"))

    return refs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--changed-files", required=True)
    parser.add_argument("--output", default="label-check-report.json")
    args = parser.parse_args()

    files = [
        f.strip() for f in args.changed_files.split("\n")
        if f.strip() and f.strip().endswith((".yaml", ".yml"))
        and f.strip().startswith("scopes/")
        and not f.strip().endswith("_scope.yaml")
    ]

    pce = get_pce()
    if not pce:
        print("PCE not configured — skipping label validation")
        with open(args.output, "w") as f:
            json.dump({"skipped": True, "reason": "PCE not configured", "missing": []}, f)
        return

    label_set = fetch_label_set(pce)
    if not label_set:
        print("Could not fetch labels from PCE — skipping label validation")
        with open(args.output, "w") as f:
            json.dump({"skipped": True, "reason": "Could not fetch labels", "missing": []}, f)
        return

    print(f"Loaded {len(label_set)} labels from PCE")

    missing = []
    for filepath in files:
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}")
            continue

        for key, value, context in extract_label_refs(data):
            if (key, value) not in label_set:
                entry = {
                    "file": filepath,
                    "label_key": key,
                    "label_value": value,
                    "context": context,
                }
                # Deduplicate: same key+value in same file only once
                if not any(
                    m["file"] == filepath and m["label_key"] == key and m["label_value"] == value
                    for m in missing
                ):
                    missing.append(entry)
                    print(f"  MISSING: {key}={value}  in {filepath}  ({context})")

    report = {
        "skipped": False,
        "total_labels_in_pce": len(label_set),
        "files_checked": len(files),
        "missing": missing,
        "has_missing": bool(missing),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    if missing:
        print(f"\nLabel check FAILED: {len(missing)} missing label reference(s) — these rules will silently match zero workloads")
        sys.exit(1)
    else:
        print(f"Label check PASSED: all label references exist in PCE ({len(files)} files checked)")


if __name__ == "__main__":
    main()
