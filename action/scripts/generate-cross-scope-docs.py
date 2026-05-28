#!/usr/bin/env python3
"""
Generate requester-side cross-scope courtesy files from canonical inbound rules.

Scopes are provider-centric: a cross-scope (extra-scope) rule is authored ONCE in
the provider's scope at

    scopes/app-<provider>_env-<env>/inbound/from-<requester>.yaml

That file is the source of truth and the only one provisioned to the PCE. This
script derives the requester-side discoverability file

    scopes/app-<requester>_env-<env>/cross-scope/to-<provider>.yaml

so a requester team can see its outbound dependencies in its own directory.
Generated files carry `generated: true`; security-check.py and provision.py skip
them. The requester's environment is assumed to match the provider's.

Usage:
  python3 generate-cross-scope-docs.py [--root .] [--check]

  --check  Do not write; exit 1 if any courtesy file is missing or out of date
           (use in the validation pipeline). Without --check, write/refresh files.
"""

import argparse
import glob
import os
import sys

import yaml

HEADER = (
    "# GENERATED FILE — DO NOT EDIT.\n"
    "# Source of truth: {source}\n"
    "# Regenerate: python3 .github/scripts/generate-cross-scope-docs.py\n"
    "\n"
)


def _scope_app_env(data):
    app = env = None
    for scope_entry in data.get("scopes", []):
        for item in scope_entry:
            if isinstance(item, dict) and isinstance(item.get("label"), dict):
                lbl = item["label"]
                app = lbl.get("app", app)
                env = lbl.get("env", env)
    return app, env


def _dedup(items):
    """Order-preserving dedup of a list of dicts."""
    seen = set()
    out = []
    for it in items:
        key = repr(sorted(it.items())) if isinstance(it, dict) else repr(it)
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


def derive(inbound_data, inbound_path):
    """Return (out_path, courtesy_dict) for one canonical inbound file."""
    provider_app, env = _scope_app_env(inbound_data)
    # Fall back to the directory name (scopes/app-<app>_env-<env>/inbound/...)
    parts = inbound_path.replace("\\", "/").split("/")
    if (provider_app is None or env is None) and len(parts) >= 3:
        dirname = parts[-3]  # app-<app>_env-<env>
        if dirname.startswith("app-") and "_env-" in dirname:
            app_part, env_part = dirname[len("app-"):].split("_env-", 1)
            provider_app = provider_app or app_part
            env = env or env_part

    fname = os.path.basename(inbound_path)
    req_app = fname[len("from-"):].rsplit(".", 1)[0] if fname.startswith("from-") else fname.rsplit(".", 1)[0]

    consumers, providers, services = [], [], []
    for rule in inbound_data.get("rules", []):
        if not isinstance(rule, dict):
            continue
        for c in rule.get("consumers", []):
            # Keep within-scope selectors (role, etc.); drop the external app label.
            if isinstance(c, dict) and isinstance(c.get("label"), dict) and set(c["label"]) == {"app"}:
                continue
            consumers.append(c)
        providers.extend(rule.get("providers", []))
        services.extend(rule.get("services", []))

    courtesy = {
        "generated": True,
        "name": f"{req_app}-to-{provider_app}",
        "description": f"Generated cross-scope dependency: {req_app} → {provider_app}. See source.",
        "type": "extra-scope",
        "source": inbound_path,
        "requester": {"scope": f"{req_app}-{env}", "consumers": _dedup(consumers)},
        "target": {"scope": f"{provider_app}-{env}", "providers": _dedup(providers)},
        "services": _dedup(services),
    }
    for meta in ("justification", "requested_by", "requested_date"):
        if inbound_data.get(meta) is not None:
            courtesy[meta] = inbound_data[meta]

    out_path = f"scopes/app-{req_app}_env-{env}/cross-scope/to-{provider_app}.yaml"
    return out_path, courtesy


def render(courtesy):
    """Render a courtesy dict to YAML text with the GENERATED header."""
    body = yaml.safe_dump(courtesy, sort_keys=False, default_flow_style=False, allow_unicode=True)
    return HEADER.format(source=courtesy.get("source", "")) + body


def find_inbound_files(root):
    return sorted(glob.glob(os.path.join(root, "scopes", "*", "inbound", "from-*.yaml")))


def generate(root=".", check=False):
    """Write (or, with check=True, verify) all requester-side courtesy files.

    Returns the list of root-relative paths that were written (or that are stale,
    in check mode). An empty list means everything is already up to date.
    """
    changed = []
    for inbound_abs in find_inbound_files(root):
        rel_inbound = os.path.relpath(inbound_abs, root).replace("\\", "/")
        with open(inbound_abs) as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict) or data.get("generated"):
            continue
        out_rel, courtesy = derive(data, rel_inbound)
        desired = render(courtesy)
        out_abs = os.path.join(root, out_rel)
        current = None
        if os.path.exists(out_abs):
            with open(out_abs) as f:
                current = f.read()
        if current == desired:
            continue
        changed.append(out_rel)
        if not check:
            os.makedirs(os.path.dirname(out_abs), exist_ok=True)
            with open(out_abs, "w") as f:
                f.write(desired)
    return changed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--check", action="store_true",
                        help="verify courtesy files are current; exit 1 on drift")
    args = parser.parse_args()

    changed = generate(args.root, check=args.check)
    if args.check:
        if changed:
            print("Cross-scope courtesy files are out of date — run generate-cross-scope-docs.py:")
            for c in changed:
                print(f"  {c}")
            sys.exit(1)
        print("Cross-scope courtesy files up to date")
        return
    if changed:
        for c in changed:
            print(f"  generated {c}")
        print(f"Generated {len(changed)} cross-scope courtesy file(s)")
    else:
        print("Cross-scope courtesy files already up to date")


if __name__ == "__main__":
    main()
