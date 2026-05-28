"""Tests for generate-cross-scope-docs.py — derive requester-side courtesy files."""
import yaml

from _loader import load

gen = load("generate-cross-scope-docs.py")

INBOUND = {
    "name": "ad-prod-inbound-from-payments",
    "description": "Inbound from payments scope",
    "type": "extra-scope",
    "enabled": True,
    "justification": "Kerberos/LDAP for PCI role enforcement.",
    "requested_by": "alice@example.com",
    "requested_date": "2026-04-15",
    "scopes": [[{"label": {"app": "ad"}}, {"label": {"env": "prod"}}]],
    "rules": [
        {
            "name": "payments-kerberos",
            "unscoped_consumers": True,
            "consumers": [{"label": {"app": "payments"}}, {"label": {"role": "processing"}}],
            "providers": [{"label": {"role": "dc"}}],
            "services": [{"port": 88, "proto": "tcp"}, {"port": 464, "proto": "tcp"}],
        },
        {
            "name": "payments-ldap",
            "unscoped_consumers": True,
            "consumers": [{"label": {"app": "payments"}}, {"label": {"role": "processing"}}],
            "providers": [{"label": {"role": "dc"}}],
            "services": [{"port": 389, "proto": "tcp"}, {"port": 636, "proto": "tcp"}],
        },
    ],
}

INBOUND_PATH = "scopes/app-ad_env-prod/inbound/from-payments.yaml"


def test_derive_output_path():
    out_path, _courtesy = gen.derive(INBOUND, INBOUND_PATH)
    assert out_path == "scopes/app-payments_env-prod/cross-scope/to-ad.yaml"


def test_derive_scopes_and_actors():
    _out, c = gen.derive(INBOUND, INBOUND_PATH)
    assert c["generated"] is True
    assert c["source"] == INBOUND_PATH
    assert c["requester"]["scope"] == "payments-prod"
    assert c["target"]["scope"] == "ad-prod"
    # requester consumers drop the app label (within-scope selectors only)
    assert c["requester"]["consumers"] == [{"label": {"role": "processing"}}]
    assert c["target"]["providers"] == [{"label": {"role": "dc"}}]
    # justification metadata carried over
    assert c["justification"] == INBOUND["justification"]
    assert c["requested_by"] == "alice@example.com"


def test_derive_unions_services_across_rules():
    _out, c = gen.derive(INBOUND, INBOUND_PATH)
    ports = sorted((s["port"], s["proto"]) for s in c["services"])
    assert ports == [(88, "tcp"), (389, "tcp"), (464, "tcp"), (636, "tcp")]


def test_render_has_generated_header_and_parses():
    _out, c = gen.derive(INBOUND, INBOUND_PATH)
    text = gen.render(c)
    assert text.lstrip().startswith("# GENERATED")
    assert INBOUND_PATH in text  # source-of-truth pointer in the header
    parsed = yaml.safe_load(text)
    assert parsed["generated"] is True
    assert parsed["target"]["scope"] == "ad-prod"


def test_generate_writes_then_is_idempotent(tmp_path):
    inbound = tmp_path / INBOUND_PATH
    inbound.parent.mkdir(parents=True, exist_ok=True)
    inbound.write_text(yaml.safe_dump(INBOUND, sort_keys=False))

    changed = gen.generate(str(tmp_path))
    out = tmp_path / "scopes/app-payments_env-prod/cross-scope/to-ad.yaml"
    assert out.exists()
    assert str(out.relative_to(tmp_path)) in [c.replace(str(tmp_path) + "/", "") for c in changed] or changed
    # second run changes nothing
    changed2 = gen.generate(str(tmp_path))
    assert changed2 == [], f"second run should be idempotent, got {changed2}"


def test_check_mode_detects_drift(tmp_path):
    inbound = tmp_path / INBOUND_PATH
    inbound.parent.mkdir(parents=True, exist_ok=True)
    inbound.write_text(yaml.safe_dump(INBOUND, sort_keys=False))
    # check before generating → drift (missing file)
    stale = gen.generate(str(tmp_path), check=True)
    assert stale, "check mode should report the missing courtesy file as drift"
    # generate, then check → no drift
    gen.generate(str(tmp_path))
    assert gen.generate(str(tmp_path), check=True) == []
