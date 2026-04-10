"""
SIEM Detection Lab REST API

Exposes the Wazuh rule engine and alert management over HTTP.
Lets you submit raw log lines and get detection results back —
useful for CI integration and testing rules without Wazuh running.

Endpoints:
    POST /api/v1/analyze           — analyze one or more log lines
    GET  /api/v1/rules             — list all rules
    GET  /api/v1/rules/<id>        — get a specific rule
    PATCH /api/v1/rules/<id>       — enable/disable a rule
    GET  /api/v1/alerts            — list recent alerts
    GET  /api/v1/stats             — alert stats and ATT&CK coverage
    POST /api/v1/replay            — replay a named scenario
    GET  /api/v1/health            — health check

Run:
    python api/app.py
"""

import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, abort
from flask_cors import CORS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

RULES_DIR = Path(__file__).parent.parent / "rules"

# ---------------------------------------------------------------------------
# Rule loader
# ---------------------------------------------------------------------------

class WazuhRule:
    def __init__(self, element: ET.Element, source_file: str = ""):
        self.rule_id = element.get("id", "")
        self.level = int(element.get("level", "0"))
        self.name = element.findtext("description", "").strip()
        self.match_text = element.findtext("match", "").strip()
        self.regex_text = element.findtext("regex", "").strip()
        self.mitre_ids = [e.text.strip() for e in element.findall(".//mitre/id") if e.text]
        self.source_file = source_file
        self.enabled = True
        self._match_re = re.compile(self.match_text, re.IGNORECASE) if self.match_text else None
        self._regex_re = re.compile(self.regex_text, re.IGNORECASE) if self.regex_text else None

    @property
    def severity(self) -> str:
        if self.level >= 13: return "critical"
        if self.level >= 10: return "high"
        if self.level >= 7:  return "medium"
        return "low"

    def matches(self, log_line: str) -> bool:
        if not self.enabled:
            return False
        if self._match_re and not self._match_re.search(log_line):
            return False
        if self._regex_re and not self._regex_re.search(log_line):
            return False
        return bool(self._match_re or self._regex_re)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "level": self.level,
            "severity": self.severity,
            "name": self.name,
            "mitre_ids": self.mitre_ids,
            "match": self.match_text,
            "regex": self.regex_text,
            "source_file": self.source_file,
            "enabled": self.enabled,
        }


def load_rules() -> list[WazuhRule]:
    rules = []
    for xml_file in sorted(RULES_DIR.rglob("*.xml")):
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for el in root.findall(".//rule") if root.tag != "rule" else [root]:
                rules.append(WazuhRule(el, source_file=str(xml_file.relative_to(RULES_DIR))))
        except ET.ParseError as e:
            logger.warning("XML parse error in %s: %s", xml_file, e)
    return rules


_rules: list[WazuhRule] = load_rules()
_rule_index: dict[str, WazuhRule] = {r.rule_id: r for r in _rules}
_alerts: list[dict] = []

# ---------------------------------------------------------------------------
# Routes — Analysis
# ---------------------------------------------------------------------------

@app.route("/api/v1/analyze", methods=["POST"])
def analyze():
    """
    Submit log lines for detection.

    Body: { "logs": ["log line 1", "log line 2", ...] }
    or a single string: { "log": "single log line" }
    """
    body = request.get_json(silent=True)
    if not body:
        abort(400, description="Request body must be JSON")

    if "log" in body:
        log_lines = [body["log"]]
    elif "logs" in body:
        log_lines = body["logs"]
    else:
        abort(400, description="Expected 'log' or 'logs' in body")

    if not log_lines:
        abort(400, description="No log lines provided")
    if len(log_lines) > 500:
        abort(400, description="Maximum 500 log lines per request")

    fired_alerts = []
    for line in log_lines:
        for rule in _rules:
            if rule.matches(line):
                alert = {
                    "alert_id": f"{rule.rule_id}-{int(datetime.now(timezone.utc).timestamp()*1000)}",
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "level": rule.level,
                    "mitre_ids": rule.mitre_ids,
                    "log_line": line,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                fired_alerts.append(alert)
                _alerts.insert(0, alert)

    if len(_alerts) > 1000:
        del _alerts[1000:]

    return jsonify({
        "logs_analyzed": len(log_lines),
        "alerts_fired": len(fired_alerts),
        "alerts": fired_alerts,
    }), 200 if fired_alerts else 204


@app.route("/api/v1/replay", methods=["POST"])
def replay_scenario():
    """
    Replay a named attack scenario.
    Body: { "scenario": "ssh_brute" }
    """
    from scripts.replay_logs import SCENARIO_LOGS
    body = request.get_json(silent=True) or {}
    scenario = body.get("scenario", "all")

    if scenario not in SCENARIO_LOGS:
        abort(400, description=f"Unknown scenario. Valid: {list(SCENARIO_LOGS.keys())}")

    logs = SCENARIO_LOGS[scenario]
    fired_alerts = []
    for line in logs:
        for rule in _rules:
            if rule.matches(line):
                fired_alerts.append({
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "mitre_ids": rule.mitre_ids,
                    "log_line": line[:100],
                })

    return jsonify({
        "scenario": scenario,
        "logs_replayed": len(logs),
        "alerts_fired": len(fired_alerts),
        "alerts": fired_alerts,
    })


# ---------------------------------------------------------------------------
# Routes — Rules
# ---------------------------------------------------------------------------

@app.route("/api/v1/rules", methods=["GET"])
def list_rules():
    severity = request.args.get("severity")
    enabled = request.args.get("enabled")
    tactic = request.args.get("tactic")

    rules = _rules
    if severity:
        rules = [r for r in rules if r.severity == severity]
    if enabled is not None:
        rules = [r for r in rules if r.enabled == (enabled.lower() == "true")]
    if tactic:
        rules = [r for r in rules if any(tactic.lower() in mid.lower() for mid in r.mitre_ids)]

    return jsonify({
        "rules": [r.to_dict() for r in rules],
        "total": len(rules),
        "enabled_count": sum(1 for r in _rules if r.enabled),
    })


@app.route("/api/v1/rules/<rule_id>", methods=["GET"])
def get_rule(rule_id: str):
    rule = _rule_index.get(rule_id)
    if not rule:
        abort(404, description=f"Rule {rule_id!r} not found")
    return jsonify(rule.to_dict())


@app.route("/api/v1/rules/<rule_id>", methods=["PATCH"])
def update_rule(rule_id: str):
    rule = _rule_index.get(rule_id)
    if not rule:
        abort(404, description=f"Rule {rule_id!r} not found")
    body = request.get_json(silent=True) or {}
    if "enabled" in body:
        rule.enabled = bool(body["enabled"])
    return jsonify(rule.to_dict())


# ---------------------------------------------------------------------------
# Routes — Alerts & Stats
# ---------------------------------------------------------------------------

@app.route("/api/v1/alerts", methods=["GET"])
def list_alerts():
    severity = request.args.get("severity")
    rule_id = request.args.get("rule_id")
    limit = min(200, int(request.args.get("limit", 50)))

    filtered = _alerts
    if severity:
        filtered = [a for a in filtered if a.get("severity") == severity]
    if rule_id:
        filtered = [a for a in filtered if a.get("rule_id") == rule_id]

    return jsonify({
        "alerts": filtered[:limit],
        "total": len(filtered),
    })


@app.route("/api/v1/stats", methods=["GET"])
def stats():
    sev_counts: dict = {}
    rule_counts: dict = {}
    mitre_counts: dict = {}

    for a in _alerts:
        sev = a.get("severity", "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        rid = a.get("rule_id", "?")
        rule_counts[rid] = rule_counts.get(rid, 0) + 1
        for mid in a.get("mitre_ids", []):
            mitre_counts[mid] = mitre_counts.get(mid, 0) + 1

    return jsonify({
        "rules": {
            "total": len(_rules),
            "enabled": sum(1 for r in _rules if r.enabled),
        },
        "alerts": {
            "total": len(_alerts),
            "by_severity": sev_counts,
            "top_rules": sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5],
        },
        "mitre_coverage": {
            "techniques_detected": len(mitre_counts),
            "top_techniques": sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True)[:5],
        },
    })


@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "rules_loaded": len(_rules),
        "alerts_in_memory": len(_alerts),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad Request", "message": str(e.description)}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not Found", "message": str(e.description)}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    logger.info("Starting SIEM Detection Lab API — %d rules loaded", len(_rules))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_ENV") == "development")
