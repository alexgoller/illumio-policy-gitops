#!/usr/bin/env python3
"""
Update README.md provision status and policy stat badges.

Reads provision-report.json and counts YAML files in scopes/, ip-lists/,
services/, then rewrites the <!-- BADGES_START --> block in README.md with
fresh shields.io badge URLs.

Usage:
  python3 update-badges.py --report provision-report.json --readme README.md
"""

import argparse
import json
import os
import re
import urllib.parse
from datetime import datetime, timezone


def _badge(label: str, message: str, color: str, style: str = "flat-square") -> str:
    def _enc(s: str) -> str:
        return urllib.parse.quote(
            s.replace("-", "--").replace("_", "__").replace(" ", "_"),
            safe="",
        )
    url = f"https://img.shields.io/badge/{_enc(label)}-{_enc(message)}-{color}?style={style}"
    return f"![{label}]({url})"


def count_policy_objects(repo_root: str = ".") -> tuple[int, int, int]:
    def _count(path: str) -> int:
        if not os.path.isdir(path):
            return 0
        return sum(
            1 for root, _, files in os.walk(path)
            for f in files
            if f.endswith((".yaml", ".yml"))
            and not f.startswith("_")
            and f != ".gitkeep"
        )
    return (
        _count(os.path.join(repo_root, "scopes")),
        _count(os.path.join(repo_root, "ip-lists")),
        _count(os.path.join(repo_root, "services")),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", default="provision-report.json")
    parser.add_argument("--readme", default="README.md")
    args = parser.parse_args()

    status = "unknown"
    try:
        with open(args.report) as f:
            report = json.load(f)
        status = report.get("status", "unknown")
    except Exception:
        pass

    rulesets, ip_lists, services = count_policy_objects()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if status == "success":
        prov_badge = _badge("provision", "success", "success")
    elif status == "error":
        prov_badge = _badge("provision", "failed", "critical")
    elif status == "skipped":
        prov_badge = _badge("provision", "skipped", "inactive")
    else:
        prov_badge = _badge("provision", status, "inactive")

    badges = "  ".join([
        prov_badge,
        _badge("last sync", now, "informational"),
        _badge("rulesets", str(rulesets), "blue"),
        _badge("ip-lists", str(ip_lists), "blue"),
        _badge("services", str(services), "blue"),
    ])

    with open(args.readme) as f:
        content = f.read()

    block = f"<!-- BADGES_START -->\n{badges}\n<!-- BADGES_END -->"
    if "<!-- BADGES_START -->" in content:
        content = re.sub(
            r"<!-- BADGES_START -->.*?<!-- BADGES_END -->",
            block,
            content,
            flags=re.DOTALL,
        )
    else:
        # Insert after the first heading line
        content = re.sub(r"(# [^\n]+\n)", r"\1\n" + block + "\n\n", content, count=1)

    with open(args.readme, "w") as f:
        f.write(content)

    print(
        f"Updated README badges: {status} · {rulesets} rulesets · "
        f"{ip_lists} ip-lists · {services} services"
    )


if __name__ == "__main__":
    main()
