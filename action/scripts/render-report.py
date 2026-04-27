#!/usr/bin/env python3
"""
Render a polished markdown PR comment from security and traffic reports.

Reads security-report.json and traffic-report.json, then reads each changed
YAML file to produce a per-ruleset breakdown with inline traffic evidence
and security findings.

Usage:
  python3 render-report.py \\
    --security security-report.json \\
    --traffic traffic-report.json \\
    --changed-files "scopes/foo/bar.yaml\\nip-lists/baz.yaml" \\
    --output pr-comment.md
"""

import argparse
import json
import os

import yaml


def _load_json(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _load_yaml(path: str) -> dict:
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _fmt_scope(scopes: list) -> str:
    """Format ruleset scopes as inline code badges."""
    parts = []
    for scope_entry in scopes:
        for item in scope_entry:
            if isinstance(item, dict) and "label" in item:
                lbl = item["label"]
                if isinstance(lbl, dict):
                    for k, v in lbl.items():
                        parts.append(f"`{k}={v}`")
    return " · ".join(parts) if parts else "_global_"


def _fmt_services(services: list) -> str:
    """Compact service list for table cells."""
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


def _fmt_evidence(ev: dict) -> tuple[str, str]:
    """Return (status_icon, evidence_text) for a traffic evidence entry."""
    if ev is None:
        return "—", "—"
    if ev.get("traffic_found"):
        conns = ev.get("blocked_connections", 0)
        sources = ev.get("unique_sources", 0)
        return "✅", f"{conns:,} blocked · {sources} src"
    reason = (ev.get("reason") or ev.get("error") or "No evidence").rstrip(".")
    # Trim long reasons
    if len(reason) > 55:
        reason = reason[:52] + "…"
    return "⚠️", reason


def render(security_path: str, traffic_path: str, changed_files_raw: str, output_path: str):
    security = _load_json(security_path)
    traffic = _load_json(traffic_path)

    files = [
        f.strip() for f in changed_files_raw.split("\n")
        if f.strip() and f.strip().endswith((".yaml", ".yml"))
    ]

    ss = security.get("summary", {})
    ts = traffic.get("summary", {})

    # Index security findings by file
    findings_by_file: dict[str, list] = {}
    for f in security.get("findings", []):
        findings_by_file.setdefault(f["file"], []).append(f)

    # Index traffic evidence by (file, rule_name)
    evidence_index: dict[tuple, dict] = {}
    for e in traffic.get("evidence", []):
        evidence_index[(e["file"], e["rule_name"])] = e

    lines = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines.append("## 🔒 Policy Change Report\n")

    summary_parts = [f"**{len(files)} file{'s' if len(files) != 1 else ''} changed**"]
    if ss.get("critical", 0):
        summary_parts.append(f"**{ss['critical']} critical ❌**")
    if ss.get("high", 0):
        summary_parts.append(f"**{ss['high']} high ⚠️**")
    if ss.get("medium", 0):
        summary_parts.append(f"{ss['medium']} medium 🔵")
    total_rules = ts.get("total_rules", 0)
    if total_rules:
        justified = ts.get("justified", 0)
        summary_parts.append(f"**{justified}/{total_rules} rules justified**")
    lines.append(" · ".join(summary_parts) + "\n")
    lines.append("---\n")

    # ── Per-file sections ────────────────────────────────────────────────────
    for filepath in files:
        if not os.path.exists(filepath):
            lines.append(f"### ~~`{os.path.basename(filepath)}`~~  _(deleted)_")
            lines.append(f"> `{filepath}`\n")
            lines.append("---\n")
            continue

        data = _load_yaml(filepath)
        ruleset_name = data.get("name") or os.path.splitext(os.path.basename(filepath))[0]
        file_findings = findings_by_file.get(filepath, [])
        is_ip_list = filepath.startswith("ip-lists/")
        is_service = filepath.startswith("services/")

        # Section header: ruleset name + file path
        lines.append(f"### `{ruleset_name}`")
        lines.append(f"> `{filepath}`")

        # Scope / type line
        if "scopes" in data and not is_ip_list and not is_service:
            scope_str = _fmt_scope(data["scopes"])
            lines.append(f"> **Scope:** {scope_str}")
        elif is_ip_list:
            n_ranges = len(data.get("ip_ranges", []))
            n_fqdns = len(data.get("fqdns", []))
            parts = []
            if n_ranges:
                parts.append(f"{n_ranges} range{'s' if n_ranges != 1 else ''}")
            if n_fqdns:
                parts.append(f"{n_fqdns} FQDN{'s' if n_fqdns != 1 else ''}")
            lines.append(f"> **Type:** IP List · {', '.join(parts) if parts else 'empty'}")
        elif is_service:
            lines.append(f"> **Type:** Service object")

        lines.append("")  # blank line after blockquote

        # ── Rules table (rulesets) ────────────────────────────────────────
        rules = data.get("rules", [])
        deny_rules = data.get("deny_rules", [])
        all_rules = [(r, "allow") for r in rules] + [(r, "deny") for r in deny_rules]

        if all_rules:
            lines.append("| | Rule | Services | Traffic Evidence |")
            lines.append("|:---:|---|---|---|")
            for rule, rule_type in all_rules:
                rule_name = rule.get("name", "(unnamed)")
                services = rule.get("services", [])
                svc_str = _fmt_services(services)

                ev = evidence_index.get((filepath, rule_name))
                icon, ev_text = _fmt_evidence(ev)

                # Deny rules always get a distinct marker
                if rule_type == "deny":
                    icon = "🚫"
                    ev_text = "Deny rule"

                # Truncate long rule names for table readability
                display_name = rule_name if len(rule_name) <= 72 else rule_name[:69] + "…"
                # Mark disabled rules
                if not rule.get("enabled", True):
                    display_name = f"~~{display_name}~~ _(disabled)_"

                lines.append(f"| {icon} | {display_name} | {svc_str} | {ev_text} |")
            lines.append("")

        # ── IP list ranges table ──────────────────────────────────────────
        elif is_ip_list:
            ip_ranges = data.get("ip_ranges", [])
            fqdns = data.get("fqdns", [])
            if ip_ranges:
                lines.append("| Range | Description |")
                lines.append("|---|---|")
                for r in ip_ranges[:15]:
                    if isinstance(r, dict):
                        ip = r.get("from_ip", "")
                        to_ip = r.get("to_ip", "")
                        desc = r.get("description", "")
                        if to_ip and to_ip != ip:
                            ip = f"{ip} – {to_ip}"
                        lines.append(f"| `{ip}` | {desc} |")
                if len(ip_ranges) > 15:
                    lines.append(f"| … | _{len(ip_ranges) - 15} more ranges_ |")
                lines.append("")
            if fqdns:
                lines.append("| FQDN |")
                lines.append("|---|")
                for fqdn in fqdns[:10]:
                    name = fqdn.get("fqdn", fqdn) if isinstance(fqdn, dict) else fqdn
                    lines.append(f"| `{name}` |")
                if len(fqdns) > 10:
                    lines.append(f"| _… {len(fqdns) - 10} more_ |")
                lines.append("")

        # ── Service object ports table ─────────────────────────────────────
        elif is_service:
            port_overrides = data.get("service_ports", [])
            windows_services = data.get("windows_services", [])
            if port_overrides:
                lines.append("| Port | Protocol | To Port |")
                lines.append("|---|---|---|")
                for p in port_overrides[:10]:
                    port = p.get("port", "")
                    proto = p.get("proto", "")
                    to_port = p.get("to_port", "")
                    lines.append(f"| {port} | {proto} | {to_port} |")
                lines.append("")

        # ── Security findings callout ─────────────────────────────────────
        if file_findings:
            for f in file_findings:
                icon = "❌" if f["action"] == "block" else "⚠️"
                rule_ref = f.get("context", "")
                ctx = f" — _{rule_ref}_" if rule_ref else ""
                lines.append(f"> {icon} **{f['rule_id']}** `{f['severity']}` — {f['message']}{ctx}")
            lines.append("")

        lines.append("---\n")

    # ── Footer summary table ─────────────────────────────────────────────────
    lines.append("### Summary\n")
    status_icon = "❌" if ss.get("blocked") else "✅"
    status_text = "**BLOCKED** — critical findings require resolution" if ss.get("blocked") else "Clear to merge"

    lines.append("| | | |")
    lines.append("|:---:|---|---|")
    lines.append(f"| {status_icon} | PR status | {status_text} |")
    lines.append(f"| 📄 | Files changed | {len(files)} |")

    crit = ss.get("critical", 0)
    high = ss.get("high", 0)
    med = ss.get("medium", 0)
    if crit or high or med:
        sec_text = " · ".join(filter(None, [
            f"{crit} critical" if crit else "",
            f"{high} high" if high else "",
            f"{med} medium" if med else "",
        ]))
        lines.append(f"| 🛡️ | Security findings | {sec_text} |")
    else:
        lines.append("| 🛡️ | Security | All checks passed |")

    if total_rules:
        justified = ts.get("justified", 0)
        unjustified = ts.get("unjustified", 0)
        ev_text = f"{justified}/{total_rules} rules justified"
        if unjustified:
            ev_text += f" · {unjustified} need review"
        lines.append(f"| 📊 | Traffic evidence | {ev_text} |")

    lines.append("")
    lines.append(
        "<sub>🤖 Generated by "
        "[Illumio Policy GitOps](https://github.com/alexgoller/illumio-policy-gitops)"
        "</sub>"
    )

    output = "\n".join(lines)
    with open(output_path, "w") as f:
        f.write(output)

    print(f"Report written: {output_path} ({len(lines)} lines, {len(output)} chars)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--security", default="security-report.json")
    parser.add_argument("--traffic", default="traffic-report.json")
    parser.add_argument("--changed-files", required=True)
    parser.add_argument("--output", default="pr-comment.md")
    args = parser.parse_args()

    render(args.security, args.traffic, args.changed_files, args.output)


if __name__ == "__main__":
    main()
