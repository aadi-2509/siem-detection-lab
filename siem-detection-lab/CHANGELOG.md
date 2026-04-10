# Changelog

## [1.0.0] — 2025-10-25

### Added
- 25 custom Wazuh detection rules across 6 MITRE ATT&CK tactics
- REST API — submit log lines, get detection results, manage rules
- Log replay tool with 8 attack scenarios
- Rule deployment script — merges XML, copies to container, reloads manager
- Alert volume tuning script with OpenSearch integration
- Docker Compose stack — Wazuh manager + indexer + dashboard
- Rule test harness — 25+ tests, runs locally without Wazuh
- GitHub Actions CI — XML validation, rule tests, API tests (3.10/3.11/3.12)

### Rules added
- 100100–100103: SSH brute force chain (single → sustained → root-targeted)
- 100110–100112: Sudo escalation and abuse
- 100200–100203: RDP and SSH lateral movement
- 100300–100321: Persistence (cron, new user, authorized_keys, sudoers)
- 100400–100420: Defense evasion (log deletion, auditd, firewall, rootkit, kernel module)
- 100500–100502: Exfiltration (staging, HTTP POST, DNS tunneling)
- 100600–100603: Discovery (port scan, nmap, AWS metadata, system enum)

---

## [0.2.0] — 2025-10-05

### Added
- Wazuh Docker Compose stack
- Log replay tool with dry-run mode
- Defense evasion rules (log deletion, auditd stop)
- Exfiltration rules (curl data POST, data staging in /tmp)

### Fixed
- SSH brute force rule chain — if_matched_sid was referencing wrong parent rule ID
- Cron detection regex was too broad, causing false positives on benign CRON entries

---

## [0.1.0] — 2025-09-15

### Added
- Initial rule set: SSH brute force, sudo escalation, lateral movement
- Basic test harness with XML parser-based rule matcher
- Deploy script skeleton
