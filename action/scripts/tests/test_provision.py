"""Tests for provision.py — services provisioning (create/update), ordering, resolution."""
import os

import yaml

from _loader import load

prov = load("provision.py")


class FakeResp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status
        self.text = ""

    def json(self):
        return self._data


class FakePCE:
    """Minimal PCE double recording call order and storing draft objects."""

    def __init__(self):
        self.services = []
        self.ip_lists = []
        self.rule_sets = []
        self.labels = []
        self.calls = []
        self._n = 0

    def _href(self, kind):
        self._n += 1
        return f"/orgs/1/sec_policy/draft/{kind}/{self._n}"

    def get(self, path, params=None):
        self.calls.append(("GET", path))
        if "services" in path:
            return FakeResp(list(self.services))
        if "ip_lists" in path:
            return FakeResp(list(self.ip_lists))
        if "rule_sets" in path:
            return FakeResp(list(self.rule_sets))
        if path == "/labels":
            return FakeResp(list(self.labels))
        return FakeResp([])

    def post(self, path, json=None):
        self.calls.append(("POST", path))
        if path == "/sec_policy":
            return FakeResp({"href": "/job/1"}, 201)
        kind = path.rstrip("/").split("/")[-1]
        obj = {**(json or {}), "href": self._href(kind)}
        if "services" in path:
            self.services.append(obj)
        elif "ip_lists" in path:
            self.ip_lists.append(obj)
        elif "rule_sets" in path:
            self.rule_sets.append(obj)
        return FakeResp(obj, 201)

    def put(self, href, json=None):
        self.calls.append(("PUT", href))
        return FakeResp({}, 200)

    def delete(self, href):
        self.calls.append(("DELETE", href))
        return FakeResp({}, 204)

    def set_credentials(self, *a, **k):
        pass

    def set_tls_settings(self, *a, **k):
        pass


def test_provision_service_creates_when_absent():
    pce = FakePCE()
    action, name = prov.provision_service(
        pce, "services/postgresql.yaml",
        {"name": "PostgreSQL", "description": "db", "service_ports": [{"port": 5432, "proto": "tcp"}]},
    )
    assert action == "created"
    assert name == "PostgreSQL"
    assert pce.services[0]["service_ports"] == [{"port": 5432, "proto": 6}]
    assert ("POST", "/sec_policy/draft/services") in pce.calls


def test_provision_service_updates_when_present():
    pce = FakePCE()
    pce.services.append({"name": "PostgreSQL", "href": "/svc/9"})
    action, name = prov.provision_service(
        pce, "services/postgresql.yaml",
        {"name": "PostgreSQL", "service_ports": [{"port": 5432, "proto": "udp"}]},
    )
    assert action == "updated"
    assert ("PUT", "/svc/9") in pce.calls


def test_provision_service_maps_udp_proto():
    pce = FakePCE()
    prov.provision_service(pce, "services/kerberos.yaml",
                           {"name": "Kerberos", "service_ports": [{"port": 88, "proto": "udp"}]})
    assert pce.services[0]["service_ports"] == [{"port": 88, "proto": 17}]


def test_delete_object_handles_services():
    pce = FakePCE()
    pce.services.append({"name": "PostgreSQL", "href": "/svc/9"})
    action, name = prov.delete_object(pce, "services/postgresql.yaml")
    assert action == "deleted"
    assert ("DELETE", "/svc/9") in pce.calls


def test_main_provisions_service_before_ruleset_and_resolves_it(tmp_path, monkeypatch):
    # A net-new service plus a ruleset that references it by name. The service must
    # be created first, and the ruleset must resolve the (newly created) service href.
    (tmp_path / "services").mkdir()
    (tmp_path / "services" / "postgresql.yaml").write_text(
        yaml.safe_dump({"name": "PostgreSQL", "service_ports": [{"port": 5432, "proto": "tcp"}]})
    )
    rs_dir = tmp_path / "scopes" / "app-shareddb_env-prod" / "inbound"
    rs_dir.mkdir(parents=True)
    (rs_dir / "from-payments.yaml").write_text(yaml.safe_dump({
        "name": "shareddb-inbound-from-payments",
        "type": "extra-scope",
        "scopes": [[{"label": {"app": "shareddb"}}, {"label": {"env": "prod"}}]],
        "rules": [{
            "name": "payments-to-db",
            "unscoped_consumers": True,
            "consumers": [{"label": {"app": "payments"}}],
            "providers": [{"label": {"role": "db"}}],
            "services": [{"name": "PostgreSQL"}],
        }],
    }))

    pce = FakePCE()
    monkeypatch.setattr(prov, "get_pce", lambda: pce)
    monkeypatch.setattr(prov, "build_caches", lambda p: ({}, {}, {}))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CHANGED_FILES", "scopes/app-shareddb_env-prod/inbound/from-payments.yaml\nservices/postgresql.yaml")
    monkeypatch.setenv("AUTO_PROVISION", "false")  # keep the assertion focused on draft writes

    prov.main()

    # service POST happened before ruleset POST despite the changed-files order
    svc_post = pce.calls.index(("POST", "/sec_policy/draft/services"))
    rs_post = pce.calls.index(("POST", "/sec_policy/draft/rule_sets"))
    assert svc_post < rs_post, f"service must be provisioned before ruleset: {pce.calls}"

    # the ruleset rule resolved the newly created service to its href
    svc_href = pce.services[0]["href"]
    assert pce.rule_sets[0]["rules"][0]["ingress_services"] == [{"href": svc_href}]


def test_main_skips_generated_courtesy_file(tmp_path, monkeypatch):
    cs_dir = tmp_path / "scopes" / "app-payments_env-prod" / "cross-scope"
    cs_dir.mkdir(parents=True)
    (cs_dir / "to-ad.yaml").write_text(yaml.safe_dump({
        "generated": True, "name": "payments-to-ad", "type": "extra-scope",
        "target": {"scope": "ad-prod"},
    }))
    pce = FakePCE()
    monkeypatch.setattr(prov, "get_pce", lambda: pce)
    monkeypatch.setattr(prov, "build_caches", lambda p: ({}, {}, {}))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CHANGED_FILES", "scopes/app-payments_env-prod/cross-scope/to-ad.yaml")
    monkeypatch.setenv("AUTO_PROVISION", "false")

    prov.main()
    # nothing created/updated on the PCE for a generated file
    assert not any(m == "POST" and "rule_sets" in p for m, p in pce.calls)
