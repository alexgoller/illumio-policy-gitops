#!/usr/bin/env python3
"""
Cross-scope mirror validation.

For every cross-scope/to-{target}.yaml in the changeset, verify a corresponding
inbound/from-{source}.yaml exists. And vice-versa. Without the mirror, one side
of a cross-scope rule is unreviewed — the target scope owner never sees the
change.

Pure filesystem check — no PCE API required.

Naming convention expected:
  scopes/app-{SOURCE}_env-{ENV}/cross-scope/to-{TARGET}.yaml
  ↔ scopes/app-{TARGET}_env-*/inbound/from-{SOURCE}.yaml

Exits 1 if any mirror is missing.

Usage:
  python3 mirror-check.py \
    --changed-files "scopes/app-payments_env-prod/cross-scope/to-ad.yaml" \
    --output mirror-check-report.json
"""

import argparse
import glob
import json
import os
import sys


def _scope_short(scope_dir: str) -> str:
    """
    Extract the short application name from a scope directory name.
    'app-payments_env-prod' → 'payments'
    'payments-prod'         → 'payments'
    """
    name = os.path.basename(scope_dir)
    if name.startswith("app-"):
        name = name[4:]
    for sep in ("_env-", "_", "-"):
        if sep in name:
            name = name[: name.index(sep)]
            break
    return name


def find_mirror(filepath: str, repo_root: str = ".") -> dict:
    """
    Given a cross-scope or inbound filepath, return a result dict describing
    whether its mirror exists.
    """
    parts = filepath.replace("\\", "/").split("/")

    # scopes / {scope_dir} / cross-scope / to-{target}.yaml
    if len(parts) >= 4 and parts[0] == "scopes" and parts[-2] == "cross-scope":
        scope_dir = parts[1]
        filename = parts[-1]
        if not filename.startswith("to-"):
            return None
        target = os.path.splitext(filename[3:])[0]
        source = _scope_short(scope_dir)

        # Try app-{target}_env-* first, then bare {target}_*
        patterns = [
            os.path.join(repo_root, f"scopes/app-{target}_*/inbound/from-{source}.yaml"),
            os.path.join(repo_root, f"scopes/{target}_*/inbound/from-{source}.yaml"),
            os.path.join(repo_root, f"scopes/{target}-*/inbound/from-{source}.yaml"),
        ]
        matches = []
        for p in patterns:
            matches.extend(glob.glob(p))

        expected = f"scopes/app-{target}_<env>/inbound/from-{source}.yaml"
        return {
            "file": filepath,
            "type": "cross-scope → inbound",
            "expected_mirror": expected,
            "found": bool(matches),
            "mirror_path": matches[0] if matches else None,
        }

    # scopes / {scope_dir} / inbound / from-{source}.yaml
    if len(parts) >= 4 and parts[0] == "scopes" and parts[-2] == "inbound":
        scope_dir = parts[1]
        filename = parts[-1]
        if not filename.startswith("from-"):
            return None
        source = os.path.splitext(filename[5:])[0]
        target = _scope_short(scope_dir)

        patterns = [
            os.path.join(repo_root, f"scopes/app-{source}_*/cross-scope/to-{target}.yaml"),
            os.path.join(repo_root, f"scopes/{source}_*/cross-scope/to-{target}.yaml"),
            os.path.join(repo_root, f"scopes/{source}-*/cross-scope/to-{target}.yaml"),
        ]
        matches = []
        for p in patterns:
            matches.extend(glob.glob(p))

        expected = f"scopes/app-{source}_<env>/cross-scope/to-{target}.yaml"
        return {
            "file": filepath,
            "type": "inbound → cross-scope",
            "expected_mirror": expected,
            "found": bool(matches),
            "mirror_path": matches[0] if matches else None,
        }

    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--changed-files", required=True)
    parser.add_argument("--output", default="mirror-check-report.json")
    args = parser.parse_args()

    files = [
        f.strip() for f in args.changed_files.split("\n")
        if f.strip() and f.strip().endswith((".yaml", ".yml"))
    ]

    results = []
    for filepath in files:
        result = find_mirror(filepath)
        if result is not None:
            results.append(result)

    missing = [r for r in results if not r["found"]]

    for r in missing:
        print(f"  MISSING MIRROR: {r['file']}")
        print(f"    Expected:      {r['expected_mirror']}")
        print(f"    Without this file the target scope owner has no PR to review.")

    report = {
        "checked": len(results),
        "missing": missing,
        "has_missing": bool(missing),
        "all": results,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    if missing:
        print(f"\nMirror check FAILED: {len(missing)} missing mirror file(s)")
        sys.exit(1)
    else:
        if results:
            print(f"Mirror check PASSED: all {len(results)} cross-scope file(s) have mirrors")
        else:
            print("Mirror check: no cross-scope or inbound files in changeset")


if __name__ == "__main__":
    main()
