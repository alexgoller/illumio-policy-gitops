#!/usr/bin/env python3
"""
Render a polished markdown PR comment from security, traffic, and resolution reports.

Reads security-report.json, traffic-report.json, and optionally
policy-resolution.json, then reads each changed YAML file to produce a
per-ruleset breakdown with inline traffic evidence, security findings,
rule-level diff markers (added/deleted/changed), and resolved IP view.

Usage:
  python3 render-report.py \\
    --security security-report.json \\
    --traffic traffic-report.json \\
    --resolution policy-resolution.json \\
    --changed-files "scopes/foo/bar.yaml\\nip-lists/baz.yaml" \\
    --diff-base origin/main \\
    --output pr-comment.md
"""

import argparse
import json
import os
import subprocess
import urllib.parse

import yaml


def _badge(label: str, message: str, color: str) -> str:
    def _enc(s: str) -> str:
        return urllib.parse.quote(
            s.replace("-", "--").replace("_", "__").replace(" ", "_"),
            safe="",
        )
    url = f"https://img.shields.io/badge/{_enc(label)}-{_enc(message)}-{color}?style=flat-square"
    return f"![{label}]({url})"


def _count_rule_changes(files: list, diff_base: str | None) -> tuple[int, int, int]:
    added = deleted = modified = 0
    for filepath in files:
        if not filepath.startswith("scopes/") or not filepath.endswith((".yaml", ".yml")):
            continue
        current_data: dict = {}
        if os.path.exists(filepath):
            try:
                with open(filepath) as f:
                    current_data = yaml.safe_load(f) or {}
            except Exception:
                pass
        base_data = _get_base_data(filepath, diff_base) if diff_base else None
        for change_type in _diff_rules(base_data, current_data).values():
            if change_type == "added":
                added += 1
            elif change_type == "deleted":
                deleted += 1
            elif change_type == "modified":
                modified += 1
    return added, deleted, modified


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


def _load_yaml_str(raw: bytes) -> dict:
    try:
        return yaml.safe_load(raw) or {}
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
    if ev.get("is_deletion_impact"):
        conns = ev.get("allowed_connections", 0)
        if ev.get("traffic_found") and conns:
            sources = ev.get("unique_sources", 0)
            return "🔴", f"**{conns:,} active connections** — removing blocks them ({sources} src)"
        return "✅", "no active traffic — safe to remove"
    if ev.get("traffic_found"):
        conns = ev.get("blocked_connections", 0)
        sources = ev.get("unique_sources", 0)
        return "✅", f"traffic found ({conns:,} blocked · {sources} src)"
    reason = (ev.get("reason") or ev.get("error") or "No evidence").rstrip(".")
    if len(reason) > 55:
        reason = reason[:52] + "…"
    return "⚠️", reason


# ---------------------------------------------------------------------------
# Rule diff helpers
# ---------------------------------------------------------------------------

def _get_base_data(filepath: str, diff_base: str) -> dict | None:
    """Load YAML data for filepath at the given git ref. Returns None if not found."""
    try:
        raw = subprocess.check_output(
            ["git", "show", f"{diff_base}:{filepath}"],
            stderr=subprocess.DEVNULL,
        )
        return _load_yaml_str(raw)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _rules_by_name(data: dict) -> dict[str, tuple[str, dict]]:
    """Extract allow+deny rules indexed by name → (rule_type, rule_dict)."""
    result = {}
    for rule in data.get("rules", []):
        if isinstance(rule, dict):
            result[rule.get("name", "(unnamed)")] = ("allow", rule)
    for rule in data.get("deny_rules", []):
        if isinstance(rule, dict):
            result[rule.get("name", "(unnamed)")] = ("deny", rule)
    return result


def _rule_fingerprint(rule: dict) -> str:
    """Stable fingerprint for a rule dict (order-independent)."""
    def _sort(obj):
        if isinstance(obj, dict):
            return {k: _sort(v) for k, v in sorted(obj.items())}
        if isinstance(obj, list):
            return [_sort(x) for x in obj]
        return obj
    return json.dumps(_sort(rule), sort_keys=True)


def _diff_rules(base_data: dict | None, current_data: dict) -> dict[str, str]:
    """
    Compare base and current rule sets.
    Returns {rule_name: "added"|"deleted"|"modified"|"unchanged"}.
    When base_data is None (new file), all current rules are "added".
    """
    current_rules = _rules_by_name(current_data)
    if base_data is None:
        return {name: "added" for name in current_rules}

    base_rules = _rules_by_name(base_data)
    status = {}
    for name in set(base_rules) | set(current_rules):
        if name not in base_rules:
            status[name] = "added"
        elif name not in current_rules:
            status[name] = "deleted"
        elif _rule_fingerprint(base_rules[name][1]) != _rule_fingerprint(current_rules[name][1]):
            status[name] = "modified"
        else:
            status[name] = "unchanged"
    return status


_DIFF_ICON = {
    "added": "🟢",
    "deleted": "🔴",
    "modified": "🟡",
    "unchanged": "",
    "": "",
}


# ---------------------------------------------------------------------------
# Main render
# ---------------------------------------------------------------------------

def render(
    security_path: str,
    traffic_path: str,
    resolution_path: str,
    changed_files_raw: str,
    output_path: str,
    diff_base: str | None,
    label_check_path: str | None = None,
    mirror_check_path: str | None = None,
):
    security = _load_json(security_path)
    traffic = _load_json(traffic_path)
    resolution = _load_json(resolution_path) if resolution_path else {}
    label_check = _load_json(label_check_path) if label_check_path else {}
    mirror_check = _load_json(mirror_check_path) if mirror_check_path else {}

    files = [
        f.strip() for f in changed_files_raw.split("\n")
        if f.strip() and f.strip().endswith((".yaml", ".yml"))
    ]

    ss = security.get("summary", {})
    ts = traffic.get("summary", {})

    # Index blast radius warnings by (file, rule_name)
    blast_index: dict[tuple, dict] = {}
    for w in resolution.get("blast_radius_warnings", []):
        blast_index[(w["file"], w["rule_name"])] = w

    # Index label check issues:
    #   label_rule_index[(file, rule_name)] = ["key=value", ...]  (for inline table flags)
    #   label_file_issues[file] = [{"label_key", "label_value", "context"}, ...]  (for callout)
    label_rule_index: dict[tuple, list[str]] = {}
    label_file_issues: dict[str, list[dict]] = {}
    for m in label_check.get("missing", []):
        filepath_m = m["file"]
        label_file_issues.setdefault(filepath_m, []).append(m)
        # Parse context: "rules.rule-name.consumers" or "deny_rules.rule-name.providers"
        ctx_parts = m.get("context", "").split(".")
        if len(ctx_parts) >= 2 and ctx_parts[0] in ("rules", "deny_rules"):
            rule_name_m = ".".join(ctx_parts[1:-1]) if len(ctx_parts) > 2 else ctx_parts[1]
            key = (filepath_m, rule_name_m)
            label_rule_index.setdefault(key, []).append(
                f"`{m['label_key']}={m['label_value']}`"
            )

    # Index security findings by file
    findings_by_file: dict[str, list] = {}
    for f in security.get("findings", []):
        findings_by_file.setdefault(f["file"], []).append(f)

    # Index traffic evidence by (file, rule_name)
    evidence_index: dict[tuple, dict] = {}
    for e in traffic.get("evidence", []):
        evidence_index[(e["file"], e["rule_name"])] = e

    # Index policy resolution by (file, rule_name)
    resolution_index: dict[tuple, dict] = {}
    for r in resolution.get("resolutions", []):
        resolution_index[(r["file"], r["rule_name"])] = r

    lines = []

    # ── Badge strip ──────────────────────────────────────────────────────────
    r_added, r_deleted, r_modified = _count_rule_changes(files, diff_base)

    badge_parts = []

    # PR status — include label/mirror/blast blocks
    lc_missing = len(label_check.get("missing", []))
    mc_missing = len(mirror_check.get("missing", []))
    br_blocked = resolution.get("has_blast_block", False)
    any_blocked = ss.get("blocked") or lc_missing or mc_missing or br_blocked
    if any_blocked:
        badge_parts.append(_badge("PR", "BLOCKED", "critical"))
    else:
        badge_parts.append(_badge("PR", "clear to merge", "success"))

    # Rule changes
    if r_added:
        badge_parts.append(_badge("rules", f"+{r_added} added", "brightgreen"))
    if r_deleted:
        badge_parts.append(_badge("rules", f"-{r_deleted} deleted", "red"))
    if r_modified:
        badge_parts.append(_badge("rules", f"~{r_modified} modified", "yellow"))
    if not (r_added or r_deleted or r_modified):
        badge_parts.append(_badge("rules", "no changes", "inactive"))

    # Security
    crit = ss.get("critical", 0)
    high = ss.get("high", 0)
    med  = ss.get("medium", 0)
    if crit:
        badge_parts.append(_badge("security", f"{crit} critical", "critical"))
    if high:
        badge_parts.append(_badge("security", f"{high} high", "orange"))
    if med:
        badge_parts.append(_badge("security", f"{med} medium", "yellow"))
    if not (crit or high or med):
        badge_parts.append(_badge("security", "clear", "success"))

    # Traffic
    total_rules = ts.get("total_rules", 0)
    justified   = ts.get("justified", 0)
    if total_rules:
        t_color = "success" if justified == total_rules else ("yellow" if justified > 0 else "orange")
        badge_parts.append(_badge("traffic", f"{justified}/{total_rules} justified", t_color))

    # Label check
    if not label_check.get("skipped"):
        if lc_missing:
            badge_parts.append(_badge("labels", f"{lc_missing} missing", "critical"))
        else:
            badge_parts.append(_badge("labels", "all valid", "success"))

    # Mirror check
    if not mirror_check.get("skipped", True):
        if mc_missing:
            badge_parts.append(_badge("mirrors", f"{mc_missing} missing", "critical"))
        else:
            badge_parts.append(_badge("mirrors", "paired", "success"))

    # ── Header ──────────────────────────────────────────────────────────────
    lines.append("## 🔒 Policy Change Report\n")
    lines.append("  ".join(badge_parts) + "\n")
    lines.append("---\n")

    # ── Per-file sections ────────────────────────────────────────────────────
    for filepath in files:
        is_ip_list = filepath.startswith("ip-lists/")
        is_service = filepath.startswith("services/")

        # ── Deleted file ─────────────────────────────────────────────────────
        if not os.path.exists(filepath):
            base_name = os.path.basename(filepath)
            lines.append(f"### ~~`{base_name}`~~  _(deleted)_")
            lines.append(f"> `{filepath}`\n")

            if diff_base and not is_ip_list and not is_service:
                base_data = _get_base_data(filepath, diff_base)
                if base_data:
                    base_rules_map = _rules_by_name(base_data)
                    if base_rules_map:
                        lines.append("| Change | Rule | Services |")
                        lines.append("|:---:|---|---|")
                        for name, (rtype, rule) in base_rules_map.items():
                            svc_str = _fmt_services(rule.get("services", []))
                            display = name if len(name) <= 72 else name[:69] + "…"
                            type_tag = " 🚫" if rtype == "deny" else ""
                            lines.append(f"| 🔴 | ~~{display}~~{type_tag} | {svc_str} |")
                        lines.append("")

            lines.append("---\n")
            continue

        data = _load_yaml(filepath)
        ruleset_name = data.get("name") or os.path.splitext(os.path.basename(filepath))[0]
        file_findings = findings_by_file.get(filepath, [])

        # Compute rule diff
        rule_diff: dict[str, str] = {}
        base_data_for_diff = None
        if diff_base:
            base_data_for_diff = _get_base_data(filepath, diff_base)
            rule_diff = _diff_rules(base_data_for_diff, data)

        # Section header
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

        # ── Rule change summary ──────────────────────────────────────────────
        if rule_diff:
            counts = {s: sum(1 for v in rule_diff.values() if v == s)
                      for s in ("added", "deleted", "modified", "unchanged")}
            change_parts = []
            if counts["added"]:
                change_parts.append(f"🟢 {counts['added']} added")
            if counts["deleted"]:
                change_parts.append(f"🔴 {counts['deleted']} deleted")
            if counts["modified"]:
                change_parts.append(f"🟡 {counts['modified']} modified")
            if counts["unchanged"]:
                change_parts.append(f"{counts['unchanged']} unchanged")
            if change_parts:
                lines.append(f"> **Changes:** {' · '.join(change_parts)}")

        lines.append("")  # blank line after blockquote

        # ── Rules table (rulesets) ────────────────────────────────────────────
        rules = data.get("rules", [])
        deny_rules = data.get("deny_rules", [])

        # Build merged list: (rule, rule_type, diff_status)
        current_rules: list[tuple] = (
            [(r, "allow", rule_diff.get(r.get("name", "(unnamed)"), "")) for r in rules]
            + [(r, "deny", rule_diff.get(r.get("name", "(unnamed)"), "")) for r in deny_rules]
        )

        # Append deleted rules from base (not present in current file)
        if diff_base and base_data_for_diff is not None:
            base_rules_map = _rules_by_name(base_data_for_diff)
            current_names = {r.get("name", "(unnamed)") for r, _, _ in current_rules}
            for name, (rtype, rule) in base_rules_map.items():
                if rule_diff.get(name) == "deleted":
                    current_rules.append((rule, rtype, "deleted"))

        if current_rules:
            show_diff_col = bool(rule_diff)
            if show_diff_col:
                lines.append("| Change | Rule | Services | Traffic Evidence |")
                lines.append("|:---:|---|---|---|")
            else:
                lines.append("| | Rule | Services | Traffic Evidence |")
                lines.append("|:---:|---|---|---|")

            for rule, rule_type, diff_status in current_rules:
                rule_name = rule.get("name", "(unnamed)")
                services = rule.get("services", [])
                svc_str = _fmt_services(services)

                diff_icon = _DIFF_ICON.get(diff_status, "")

                if diff_status == "deleted":
                    # No traffic evidence for deleted rules
                    display_name = rule_name if len(rule_name) <= 72 else rule_name[:69] + "…"
                    type_tag = " 🚫" if rule_type == "deny" else ""
                    lines.append(f"| {diff_icon} | ~~{display_name}~~{type_tag} | ~~{svc_str}~~ | — |")
                    continue

                ev = evidence_index.get((filepath, rule_name))
                ev_icon, ev_text = _fmt_evidence(ev)

                if rule_type == "deny":
                    ev_icon = "🚫"
                    ev_text = "Deny rule"

                display_name = rule_name if len(rule_name) <= 72 else rule_name[:69] + "…"
                if not rule.get("enabled", True):
                    display_name = f"~~{display_name}~~ _(disabled)_"

                # Blast radius inline flag
                br = blast_index.get((filepath, rule_name))
                if br:
                    br_icon = "🔴" if br["level"] == "block" else "⚠️"
                    display_name = f"{display_name} {br_icon} _{br['blast_radius']} workloads_"

                # Missing label inline flag — rule will silently match zero workloads
                missing_labels = label_rule_index.get((filepath, rule_name))
                if missing_labels:
                    labels_str = ", ".join(missing_labels)
                    display_name = f"{display_name} ❌ _missing label: {labels_str}_"

                # Combine ev_icon + ev_text in the evidence cell
                ev_cell = f"{ev_icon} {ev_text}" if ev_icon not in ("—",) else ev_text
                lines.append(f"| {diff_icon} | {display_name} | {svc_str} | {ev_cell} |")

            lines.append("")

        # ── IP list ranges table ──────────────────────────────────────────────
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

        # ── Service object ports table ────────────────────────────────────────
        elif is_service:
            port_overrides = data.get("service_ports", [])
            if port_overrides:
                lines.append("| Port | Protocol | To Port |")
                lines.append("|---|---|---|")
                for p in port_overrides[:10]:
                    port = p.get("port", "")
                    proto = p.get("proto", "")
                    to_port = p.get("to_port", "")
                    lines.append(f"| {port} | {proto} | {to_port} |")
                lines.append("")

        # ── Policy resolution (IP view) ──────────────────────────────────────
        res_entries = [
            r for r in resolution.get("resolutions", [])
            if r.get("file") == filepath
        ]
        if res_entries and not is_ip_list and not is_service:
            lines.append("<details>")
            lines.append("<summary>🔍 Resolved Policy — IP view</summary>\n")
            lines.append("| Rule | Consumer IPs | Provider IPs | Services |")
            lines.append("|---|---|---|---|")
            for r in res_entries:
                rname = r["rule_name"]
                if len(rname) > 50:
                    rname = rname[:47] + "…"
                cons = r.get("consumers", {})
                prov = r.get("providers", {})

                def _fmt_actor(a: dict) -> str:
                    wc = a.get("workload_count", 0)
                    ips = a.get("ips", [])
                    ipl = a.get("ip_lists", [])
                    if ipl:
                        return f"IP List: {', '.join(ipl)}"
                    if not ips:
                        return f"{a.get('label_desc', '?')} (0 hosts)"
                    if wc <= 3:
                        return ", ".join(ips[:6]) + (f" +{len(ips)-6}" if len(ips) > 6 else "")
                    return f"{', '.join(ips[:3])} … ({wc} hosts)"

                lines.append(
                    f"| {rname} | {_fmt_actor(cons)} | {_fmt_actor(prov)} | {r.get('services', '')} |"
                )
            lines.append("")
            lines.append("</details>\n")

        # ── Security findings callout ─────────────────────────────────────────
        if file_findings:
            for f in file_findings:
                if f["action"] == "block":
                    icon = "❌"
                    pr_impact = " — **blocks this PR**"
                else:
                    icon = "⚠️"
                    pr_impact = " — _potentially blocks this PR_"
                rule_ref = f.get("context", "")
                ctx = f" · _{rule_ref}_" if rule_ref else ""
                lines.append(f"> {icon} **{f['rule_id']}** `{f['severity']}` — {f['message']}{pr_impact}{ctx}")
            lines.append("")

        # ── Missing label callout ─────────────────────────────────────────────
        file_label_missing = label_file_issues.get(filepath, [])
        if file_label_missing:
            lines.append("> **❌ Label validation failed — blocks this PR**")
            lines.append(">")
            lines.append("> Rules referencing labels that do not exist in PCE will silently match")
            lines.append("> **zero workloads** — the policy looks valid but enforces nothing.")
            lines.append(">")
            lines.append("> | Label | Context | Action |")
            lines.append("> |---|---|---|")
            for m in file_label_missing:
                ctx_parts = m.get("context", "").split(".")
                if len(ctx_parts) >= 3 and ctx_parts[0] in ("rules", "deny_rules"):
                    rule_ref = ".".join(ctx_parts[1:-1])
                    field = ctx_parts[-1]
                    ctx_str = f"rule `{rule_ref}` → {field}"
                elif ctx_parts[0] == "scopes":
                    ctx_str = "scope constraint"
                else:
                    ctx_str = m.get("context", "")
                lines.append(
                    f"> | `{m['label_key']}={m['label_value']}` | {ctx_str} |"
                    f" Create label or fix typo |"
                )
            lines.append("")

        lines.append("---\n")

    # ── Footer summary table ─────────────────────────────────────────────────
    lines.append("### Summary\n")
    block_reasons = []
    if ss.get("blocked"):
        block_reasons.append("critical security findings")
    if lc_missing:
        block_reasons.append(f"{lc_missing} missing label(s)")
    if mc_missing:
        block_reasons.append(f"{mc_missing} missing mirror file(s)")
    if br_blocked:
        block_reasons.append("blast radius exceeded")
    status_icon = "❌" if block_reasons else "✅"
    status_text = (
        f"**BLOCKED** — {', '.join(block_reasons)}" if block_reasons else "Clear to merge"
    )

    lines.append("| | | |")
    lines.append("|:---:|---|---|")
    lines.append(f"| {status_icon} | PR status | {status_text} |")
    lines.append(f"| 📄 | Files changed | {len(files)} |")

    crit = ss.get("critical", 0)
    high = ss.get("high", 0)
    med = ss.get("medium", 0)
    if crit or high or med:
        sec_parts = []
        if crit:
            sec_parts.append(f"{crit} critical — **blocks this PR**")
        if high:
            sec_parts.append(f"{high} high — _potentially blocks this PR_")
        if med:
            sec_parts.append(f"{med} medium — _potentially blocks this PR_")
        lines.append(f"| 🛡️ | Security findings | {' · '.join(sec_parts)} |")
    else:
        lines.append("| 🛡️ | Security | All checks passed |")

    if total_rules:
        justified = ts.get("justified", 0)
        unjustified = ts.get("unjustified", 0)
        ev_text = f"{justified}/{total_rules} rules justified"
        if unjustified:
            ev_text += f" · {unjustified} need review"
        lines.append(f"| 📊 | Traffic evidence | {ev_text} |")

    if resolution.get("total_workloads"):
        lines.append(
            f"| 🖥️ | Policy resolution | {len(resolution.get('resolutions', []))} rules resolved"
            f" · {resolution['total_workloads']} workloads |"
        )

    # Label check
    if not label_check.get("skipped"):
        files_checked = label_check.get("files_checked", 0)
        pce_total = label_check.get("total_labels_in_pce", 0)
        pce_str = f" · PCE has {pce_total:,} labels" if pce_total else ""
        if lc_missing:
            affected_files = len({m["file"] for m in label_check.get("missing", [])})
            lines.append(
                f"| ❌ | Label validation | {lc_missing} missing ref(s) across {affected_files} file(s)"
                f" — **blocks this PR**{pce_str} |"
            )
        else:
            lines.append(
                f"| ✅ | Label validation | All references valid · {files_checked} file(s) checked{pce_str} |"
            )

    # Mirror check
    if not mirror_check.get("skipped", True) and mirror_check.get("checked", 0) > 0:
        if mc_missing:
            mc_items = "; ".join(
                f"`{m['expected_mirror']}`"
                for m in mirror_check.get("missing", [])[:3]
            )
            lines.append(f"| ❌ | Cross-scope mirrors | {mc_missing} missing — **blocks this PR** · {mc_items} |")
        else:
            lines.append(f"| ✅ | Cross-scope mirrors | All {mirror_check['checked']} cross-scope pair(s) have mirrors |")

    # Blast radius
    br_warnings = resolution.get("blast_radius_warnings", [])
    if br_warnings:
        br_blocks = [w for w in br_warnings if w["level"] == "block"]
        br_warns  = [w for w in br_warnings if w["level"] == "warn"]
        br_parts = []
        if br_blocks:
            br_parts.append(f"{len(br_blocks)} blocking (>{resolution.get('blast_radius_warnings', [{}])[0].get('blast_radius', '')} workloads)")
        if br_warns:
            br_parts.append(f"{len(br_warns)} warning")
        lines.append(f"| {'❌' if br_blocks else '⚠️'} | Blast radius | {' · '.join(br_parts)} |")

    # FW change request files — show link when they exist in the PR branch
    if os.path.exists("fw-changes/fw-change-request.csv"):
        try:
            with open("fw-changes/fw-change-request.json") as _f:
                import json as _json
                _fw = _json.load(_f)
            _s = _fw.get("summary", {})
            _total = _s.get("total_fw_tuples", 0)
            _added = _s.get("added", 0)
            _deleted = _s.get("deleted", 0)
            fw_detail = f"{_total} tuples"
            if _added or _deleted:
                fw_detail += f" · ➕{_added} ➖{_deleted}"
        except Exception:
            fw_detail = "generated"
        lines.append(f"| 🔥 | FW change request | {fw_detail} · `fw-changes/fw-change-request.csv` |")

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
    parser.add_argument("--resolution", default=None)
    parser.add_argument("--changed-files", required=True)
    parser.add_argument("--diff-base", default=None,
                        help="Git ref to compare against for rule diff (e.g. origin/main)")
    parser.add_argument("--label-check", default=None)
    parser.add_argument("--mirror-check", default=None)
    parser.add_argument("--output", default="pr-comment.md")
    args = parser.parse_args()

    render(
        args.security,
        args.traffic,
        args.resolution,
        args.changed_files,
        args.output,
        args.diff_base,
        label_check_path=args.label_check,
        mirror_check_path=args.mirror_check,
    )


if __name__ == "__main__":
    main()
