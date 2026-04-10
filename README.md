# SIEM Detection Engineering Lab

[![CI](https://github.com/yourusername/siem-detection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/siem-detection-lab/actions)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A hands-on Wazuh detection engineering environment with 25 custom correlation rules mapped to MITRE ATT&CK. Includes a REST API for testing rules without a running Wazuh instance, a log replay tool for feeding attack scenarios into the detection engine, and a tuning script that analyzes alert volume to reduce false positives.

**Built by:** Aaditya Modi — M.S. Cybersecurity, Arizona State University

---

## What it does

- 25 custom Wazuh correlation rules across 6 MITRE ATT&CK tactics
- REST API — submit raw log lines and get back which rules fired, severity, and MITRE IDs
- Log replay tool — feeds sanitized real-world attack log samples into the detection engine
- Rule deployment script — packages all XML rules and deploys to the Wazuh container in one command
- Alert volume tuning script — identifies rules that are too noisy or silently broken
- Docker Compose stack — full Wazuh manager + indexer + dashboard on your local machine
- Full test suite — 55 tests covering rule logic and API endpoints, runs without Wazuh

---

## MITRE ATT&CK coverage

| Tactic | Rules | Key techniques |
|--------|-------|----------------|
| Credential Access | 4 | T1110 (brute force), T1548.003 (sudo abuse) |
| Lateral Movement | 4 | T1021.001 (RDP), T1021.004 (SSH) |
| Persistence | 6 | T1053.003 (cron), T1136.001 (new user), T1098.004 (SSH keys) |
| Defense Evasion | 7 | T1070.002 (log deletion), T1014 (rootkit), T1562 (disable tools) |
| Exfiltration | 3 | T1048.003 (HTTP POST), T1048.001 (DNS tunnel), T1074.001 (staging) |
| Discovery | 4 | T1046 (port scan), T1552.005 (metadata), T1082 (system info) |

---

## Project structure

```
siem-detection-lab/
|-- rules/
|   |-- credential_access/
|   |   |-- 100100_ssh_brute_force.xml   # SSH brute force chain (T1110)
|   |   +-- 100103_sudo_escalation.xml   # Sudo abuse (T1548.003)
|   |-- lateral_movement/
|   |   +-- 100200_rdp_ssh_lateral.xml   # RDP + SSH lateral movement
|   |-- persistence/
|   |   +-- 100300_persistence.xml       # Cron, new user, SSH keys, sudoers
|   |-- defense_evasion/
|   |   +-- 100400_defense_evasion.xml   # Log deletion, rootkit, kernel module
|   +-- exfiltration/
|       +-- 100500_exfil_discovery.xml   # Exfil + discovery rules
|-- api/
|   +-- app.py                           # Flask REST API
|-- scripts/
|   |-- replay_logs.py                   # Attack log replay tool
|   |-- deploy_rules.py                  # Deploy rules to Wazuh container
|   |-- tune_rules.py                    # Alert volume analysis
|   +-- wait_for_wazuh.sh                # Health check script
|-- tests/
|   |-- test_rules.py                    # Rule unit tests (25 tests)
|   |-- test_api.py                      # API integration tests (30 tests)
|   +-- samples/                         # Sanitized real attack log files
|-- .github/workflows/
|   +-- ci.yml                           # GitHub Actions CI
|-- docker-compose.yml                   # Wazuh stack
|-- .env.example
|-- requirements.txt
|-- CHANGELOG.md
+-- README.md
```

---

## Prerequisites

- Python 3.10 or higher — https://python.org/downloads
- Git — https://git-scm.com
- Docker Desktop (only needed for full Wazuh stack) — https://docker.com/products/docker-desktop

---

## Option A — Local API testing (no Docker, 5 minutes)

Use this to test all 25 rules and the REST API without installing anything else.

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/siem-detection-lab.git
cd siem-detection-lab
```

### 2. Create and activate a virtual environment

Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

macOS / Linux:
```bash
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the test suite

```bash
pytest tests/ -v
```

Expected — 55 tests, all green:
```
PASSED TestRuleStructure::test_all_rules_have_ids
PASSED TestRuleStructure::test_all_rules_have_mitre_mapping
PASSED TestSSHBruteForce::test_fires_on_failed_password
PASSED TestSSHBruteForce::test_does_not_fire_on_successful_login
PASSED TestLogDeletion::test_fires_on_rm_var_log
PASSED TestPersistence::test_fires_on_new_user
PASSED TestExfiltration::test_fires_on_curl_data_post
PASSED TestDiscovery::test_fires_on_nmap
...
55 passed in 1.1s
```

### 5. Start the REST API

```bash
python api/app.py
```

```
Starting SIEM Detection Lab API -- 25 rules loaded
* Running on http://0.0.0.0:8000
```

Keep this running. Open a new terminal for the commands below.

---

## REST API usage

### Health check
```bash
curl http://localhost:8000/api/v1/health
```

```json
{ "status": "healthy", "rules_loaded": 25 }
```

### Analyze a log line

```bash
# SSH brute force -- will trigger rule 100100 and 100103
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "Oct  1 14:22:11 bastion sshd[12341]: Failed password for root from 45.142.212.100 port 54321 ssh2"}'
```

```json
{
  "alerts_fired": 2,
  "alerts": [
    { "rule_id": "100100", "rule_name": "Failed SSH login attempt", "severity": "low", "mitre_ids": ["T1110"] },
    { "rule_id": "100103", "rule_name": "SSH login attempt targeting root account", "severity": "high", "mitre_ids": ["T1110"] }
  ]
}
```

```bash
# Log deletion -- will trigger rule 100401 (critical, level 14)
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "root: rm -f /var/log/auth.log /var/log/syslog"}'
```

```bash
# Benign successful login -- no alert fires, returns HTTP 204
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "Accepted publickey for deploy from 10.0.0.5 port 22 ssh2"}'
```

### Analyze multiple log lines at once

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      "Failed password for root from 45.142.212.100 port 22 ssh2",
      "rm -f /var/log/auth.log",
      "new user: name=backdoor, UID=1337",
      "Accepted publickey for deploy from 10.0.0.5"
    ]
  }'
```

### Replay a named attack scenario

```bash
# Available: ssh_brute, log_deletion, cron_modification, new_user,
#            lateral_movement, port_scan, exfiltration, sudo_abuse, all

curl -X POST http://localhost:8000/api/v1/replay \
  -H "Content-Type: application/json" \
  -d '{"scenario": "ssh_brute"}'

curl -X POST http://localhost:8000/api/v1/replay \
  -H "Content-Type: application/json" \
  -d '{"scenario": "all"}'
```

### List all detection rules

```bash
curl http://localhost:8000/api/v1/rules
curl "http://localhost:8000/api/v1/rules?severity=critical"
```

### Disable and re-enable a rule

```bash
curl -X PATCH http://localhost:8000/api/v1/rules/100401 \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

curl -X PATCH http://localhost:8000/api/v1/rules/100401 \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

### View all alerts and MITRE coverage stats

```bash
curl http://localhost:8000/api/v1/alerts
curl "http://localhost:8000/api/v1/alerts?severity=critical"
curl http://localhost:8000/api/v1/stats
```

---

## Option B — Full Wazuh stack with visual dashboard (needs Docker)

### 1. Make sure Docker Desktop is running

Open Docker Desktop and wait until you see "Engine running" in the bottom left.

### 2. Create environment file

```bash
cp .env.example .env
```

The default values work for local testing.

### 3. Start the Wazuh stack

```bash
docker-compose up -d
```

First run downloads about 2GB. Takes 5-15 minutes. Subsequent starts take about 30 seconds.

Check everything started:
```bash
docker-compose ps
```

All three services should show "Up":
```
siem-wazuh-manager    Up
siem-wazuh-indexer    Up
siem-wazuh-dashboard  Up
```

### 4. Deploy your custom rules into Wazuh

```bash
python scripts/deploy_rules.py
```

```
Found 6 rule file(s)
  credential_access/100100_ssh_brute_force.xml
  defense_evasion/100400_defense_evasion.xml
  ...
Done. Rules deployed and manager reloaded.
```

### 5. Replay attack logs through Wazuh

```bash
python scripts/replay_logs.py --scenario all --host localhost --port 514
```

Sends 42 attack log lines into Wazuh. Each line that matches a rule fires an alert.

Try specific scenarios:
```bash
python scripts/replay_logs.py --scenario ssh_brute --count 8 --host localhost --port 514
python scripts/replay_logs.py --scenario log_deletion --host localhost --port 514
python scripts/replay_logs.py --scenario exfiltration --host localhost --port 514
```

### 6. Open the Wazuh dashboard

1. Open Chrome or Edge
2. Go to https://localhost
3. You will see a security warning -- click Advanced then Proceed to localhost
4. Login: username admin, password SecurePassword123
5. Click Security Events in the left menu
6. You will see your alerts appearing with MITRE ATT&CK technique IDs

### 7. Run the alert tuning script

```bash
python scripts/tune_rules.py --opensearch http://localhost:9200 --hours 1
```

Output shows alert volume per rule and flags anything too noisy or silent:
```
Rule ID      Count  Name                           Status
100100           8  Failed SSH login               OK
100401           4  Log deletion                   OK
100300           0  Cron modification              NOT SEEN -- check deployment
```

### 8. Stop everything when done

```bash
docker-compose down
```

---

## Adding a new rule

1. Create a new XML file in `rules/<tactic>/` using the next available ID
2. Add a comment block explaining the threshold choice
3. Add at least one test in `tests/test_rules.py`
4. Deploy with `python scripts/deploy_rules.py`
5. Update the coverage table in this README and CHANGELOG.md

Rule ID ranges:

| Range | Tactic |
|-------|--------|
| 100100-100199 | Credential Access |
| 100200-100299 | Lateral Movement |
| 100300-100399 | Persistence |
| 100400-100499 | Defense Evasion |
| 100500-100599 | Exfiltration |
| 100600-100699 | Discovery |

---

## Environment variables

| Variable | Description | Required for |
|----------|-------------|--------------|
| WAZUH_HOST | Wazuh manager host | Log replay |
| WAZUH_PORT | Wazuh manager port | Log replay |
| OPENSEARCH_URL | OpenSearch URL | Tuning script |
| INDEXER_PASSWORD | Stack password | Docker Compose |
| PORT | API port (default 8000) | API |
| FLASK_ENV | development enables debug | API |

---

## License

MIT
