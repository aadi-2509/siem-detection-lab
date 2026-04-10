# SIEM Detection Engineering Lab

A hands-on Wazuh detection engineering environment I built to practice writing SIEM correlation rules, tuning alert thresholds, and mapping detections to MITRE ATT&CK.

The lab runs on a single machine using Docker Compose — Wazuh manager, a test agent, and Kibana for visualization. The `rules/` directory has 25+ custom correlation rules I wrote covering the most common attack patterns I've seen in the wild and in CTF environments.

---

## What's in here

- **25+ custom Wazuh rules** organized by MITRE ATT&CK tactic
- **A log replay tool** that feeds pre-collected samples into the detection engine so you can see rules fire without waiting for real attacks
- **Tuning scripts** that analyze alert volume and suggest sensitivity adjustments
- **Kibana dashboards** (exported JSON) showing the ATT&CK coverage heatmap
- **A test harness** that validates rules against known-good and known-bad log samples

---

## Tactics covered

| Tactic | Rules | Key TTPs |
|--------|-------|----------|
| Credential Access | 5 | T1110 (brute force), T1552 (credentials in files), T1003 (OS credential dumping) |
| Lateral Movement | 4 | T1021 (remote services), T1550 (pass-the-hash) |
| Persistence | 5 | T1053 (cron), T1547 (startup items), T1136 (create account) |
| Defense Evasion | 5 | T1070 (log deletion), T1014 (rootkit), T1562 (disable tools) |
| Exfiltration | 3 | T1048 (exfil over alternative protocol), T1567 (exfil over web) |
| Discovery | 4 | T1046 (network scan), T1580 (cloud infra), T1082 (system info) |

---

## Prerequisites

- Docker + Docker Compose
- Python 3.10+
- ~4GB RAM for Wazuh + Kibana

---

## Quick start

```bash
git clone https://github.com/yourusername/siem-detection-lab.git
cd siem-detection-lab

# Start the stack (takes 2-3 minutes first time)
docker-compose up -d

# Wait for Wazuh to be ready
./scripts/wait_for_wazuh.sh

# Deploy custom rules to the Wazuh manager container
python scripts/deploy_rules.py

# Replay attack log samples to trigger detections
python scripts/replay_logs.py --scenario all --count 50

# Open Kibana dashboards
open http://localhost:5601
```

Default Kibana credentials: `admin / SecurePassword123`

---

## Project structure

```
siem-detection-lab/
├── rules/
│   ├── credential_access/
│   │   ├── 100100_ssh_brute_force.xml
│   │   ├── 100101_password_spray.xml
│   │   ├── 100102_credential_files.xml
│   │   ├── 100103_sudo_escalation.xml
│   │   └── 100104_kerberoasting.xml
│   ├── lateral_movement/
│   │   ├── 100200_rdp_lateral.xml
│   │   ├── 100201_ssh_lateral.xml
│   │   ├── 100202_psexec_indicators.xml
│   │   └── 100203_wmi_remote.xml
│   ├── persistence/
│   │   ├── 100300_cron_modification.xml
│   │   ├── 100301_new_user_created.xml
│   │   ├── 100302_startup_item.xml
│   │   ├── 100303_ssh_authorized_keys.xml
│   │   └── 100304_sudoers_modified.xml
│   ├── defense_evasion/
│   │   ├── 100400_log_deletion.xml
│   │   ├── 100401_rootkit_indicator.xml
│   │   ├── 100402_process_hiding.xml
│   │   ├── 100403_audit_disabled.xml
│   │   └── 100404_firewall_stopped.xml
│   ├── exfiltration/
│   │   ├── 100500_data_staged_tmp.xml
│   │   ├── 100501_suspicious_outbound.xml
│   │   └── 100502_large_dns_query.xml
│   └── discovery/
│       ├── 100600_port_scan.xml
│       ├── 100601_host_enumeration.xml
│       ├── 100602_cloud_metadata.xml
│       └── 100603_active_directory_enum.xml
├── dashboards/
│   └── mitre_coverage.ndjson
├── scripts/
│   ├── deploy_rules.py
│   ├── replay_logs.py
│   ├── tune_rules.py
│   └── wait_for_wazuh.sh
├── tests/
│   ├── samples/
│   │   ├── ssh_brute_force.log
│   │   ├── cron_modification.log
│   │   └── log_deletion.log
│   └── test_rules.py
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## Writing a new rule

Rules live in `rules/<tactic>/`. Each file contains one or more Wazuh XML rule definitions. The naming convention is `<id>_<short_name>.xml`.

Example — detecting `sudo` usage that escalates to root:

```xml
<group name="local,syslog,sudo,">
  <rule id="100103" level="8">
    <if_sid>5402</if_sid>
    <field name="dstuser">^root$</field>
    <description>Sudo privilege escalation to root detected</description>
    <options>no_full_log</options>
    <mitre>
      <id>T1548.003</id>
    </mitre>
  </rule>
</group>
```

After adding a rule, deploy it and run the tests:

```bash
python scripts/deploy_rules.py
pytest tests/test_rules.py -v -k "test_sudo"
```

---

## Tuning

The `tune_rules.py` script analyzes alert volume from the last 24h and flags rules that are firing too much (likely too sensitive) or too little (might be misconfigured):

```bash
python scripts/tune_rules.py --threshold-high 50 --threshold-low 0
```

Output:
```
Rule 100100 (SSH brute force):      142 alerts — consider raising threshold
Rule 100301 (New user created):       0 alerts — check if rule is deployed
Rule 100403 (Audit disabled):         3 alerts — within normal range
```

---

## Running tests

```bash
pytest tests/ -v
```

The test harness feeds known-bad log lines to the rule engine and asserts that the right rule IDs fire. No running Wazuh instance needed — tests use a lightweight XML parser and regex matcher that replicates Wazuh's evaluation logic.

---

## Notes

- Rule IDs start at 100100 to avoid conflicts with Wazuh's built-in rules (1–99999)
- Level 7–9: informational/medium; level 10–12: high; level 13–15: critical
- The `<options>no_full_log</options>` tag is useful for noisy rules — it prevents full log lines from being stored for every alert

---

## License

MIT
