"""Tests for security-check.py — focus on SEC-010 provider-centric placement."""
import os

import yaml

from _loader import load

sc = load("security-check.py")


def _rules():
    rules, exemptions = sc.DEFAULT_RULES, []
    return rules, exemptions


def _write(tmp_path, relpath, data):
    p = tmp_path / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(data, sort_keys=False))
    return str(p)


# --- canonical provider-side file (the real template shape) must pass clean ---

CANONICAL_INBOUND = {
    "name": "ad-prod-inbound-from-payments",
    "type": "extra-scope",
    "enabled": True,
    "justification": "Payments needs Kerberos/LDAP against AD for PCI role enforcement.",
    "scopes": [[{"label": {"app": "ad"}}, {"label": {"env": "prod"}}]],
    "rules": [
        {
            "name": "payments-kerberos",
            "unscoped_consumers": True,
            "consumers": [{"label": {"app": "payments"}}, {"label": {"role": "processing"}}],
            "providers": [{"label": {"role": "dc"}}],
            "services": [{"port": 88, "proto": "tcp"}],
        }
    ],
}


def test_sec010_correct_provider_placement_passes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fp = _write(tmp_path, "scopes/app-ad_env-prod/inbound/from-payments.yaml", CANONICAL_INBOUND)
    rules, ex = _rules()
    findings = sc.analyze_file(fp, rules, ex)
    sec010 = [f for f in findings if f["rule_id"] == "SEC-010"]
    assert sec010 == [], f"expected no SEC-010 finding on correctly-placed rule, got {sec010}"


def test_sec004_does_not_fire_when_justification_present(tmp_path, monkeypatch):
    # The canonical file carries justification, so SEC-004 must stay silent.
    monkeypatch.chdir(tmp_path)
    fp = _write(tmp_path, "scopes/app-ad_env-prod/inbound/from-payments.yaml", CANONICAL_INBOUND)
    rules, ex = _rules()
    findings = sc.analyze_file(fp, rules, ex)
    assert [f for f in findings if f["rule_id"] == "SEC-004"] == []


# --- misplacement: rule filed in the consumer's scope (consumer app == scope app) ---

def test_sec010_flags_rule_filed_in_consumer_scope(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    misplaced = dict(CANONICAL_INBOUND)
    # Same rule but enclosing scope is the *consumer's* (payments) scope — wrong.
    misplaced = {
        **CANONICAL_INBOUND,
        "scopes": [[{"label": {"app": "payments"}}, {"label": {"env": "prod"}}]],
    }
    fp = _write(tmp_path, "scopes/app-payments_env-prod/inbound/from-payments.yaml", misplaced)
    rules, ex = _rules()
    findings = sc.analyze_file(fp, rules, ex)
    sec010 = [f for f in findings if f["rule_id"] == "SEC-010"]
    assert len(sec010) == 1, f"expected one SEC-010 finding, got {sec010}"
    assert sec010[0]["action"] == "warn"
    assert sec010[0]["severity"] == "medium"


# --- misplacement: providers name a different app than the enclosing scope ---

def test_sec010_flags_provider_app_mismatch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = {
        "name": "wrong",
        "type": "extra-scope",
        "scopes": [[{"label": {"app": "ad"}}, {"label": {"env": "prod"}}]],
        "rules": [
            {
                "name": "bad-rule",
                "unscoped_consumers": True,
                "consumers": [{"label": {"app": "payments"}}],
                # providers explicitly name a *different* app than the scope (ad)
                "providers": [{"label": {"app": "shareddb"}}, {"label": {"role": "db"}}],
                "services": [{"port": 5432, "proto": "tcp"}],
            }
        ],
    }
    fp = _write(tmp_path, "scopes/app-ad_env-prod/inbound/from-payments.yaml", data)
    rules, ex = _rules()
    findings = sc.analyze_file(fp, rules, ex)
    sec010 = [f for f in findings if f["rule_id"] == "SEC-010"]
    assert len(sec010) == 1, f"expected provider-mismatch SEC-010 finding, got {sec010}"


# --- legacy requester/target courtesy schema is flagged as deprecated ---

def test_sec010_flags_legacy_requester_target_schema(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    legacy = {
        "name": "payments-to-ad",
        "type": "extra-scope",
        "requester": {"scope": "payments-prod", "consumers": [{"label": {"role": "processing"}}]},
        "target": {"scope": "ad-prod", "providers": [{"label": {"role": "dc"}}]},
        "services": [{"port": 88, "proto": "tcp"}],
        "justification": "x",
    }
    fp = _write(tmp_path, "scopes/app-payments_env-prod/cross-scope/to-ad.yaml", legacy)
    rules, ex = _rules()
    findings = sc.analyze_file(fp, rules, ex)
    sec010 = [f for f in findings if f["rule_id"] == "SEC-010"]
    assert len(sec010) == 1
    assert "deprecated" in sec010[0]["message"].lower()


# --- generated files are skipped entirely ---

def test_generated_file_is_skipped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gen = {
        "generated": True,
        "name": "payments-to-ad",
        "type": "extra-scope",
        "requester": {"scope": "payments-prod"},
        "target": {"scope": "ad-prod"},
    }
    fp = _write(tmp_path, "scopes/app-payments_env-prod/cross-scope/to-ad.yaml", gen)
    rules, ex = _rules()
    findings = sc.analyze_file(fp, rules, ex)
    assert findings == [], f"generated files must not produce findings, got {findings}"
