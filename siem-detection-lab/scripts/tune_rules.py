#!/usr/bin/env python3
"""
tune_rules.py — analyze alert volume and suggest sensitivity adjustments.

Queries the OpenSearch/Elasticsearch backend for alert counts per rule
over the last N hours, then flags rules that are too noisy or suspiciously quiet.

Usage:
    python scripts/tune_rules.py
    python scripts/tune_rules.py --hours 48 --threshold-high 100 --threshold-low 0
    python scripts/tune_rules.py --opensearch http://localhost:9200
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

OPENSEARCH_URL = "http://localhost:9200"
WAZUH_INDEX = "wazuh-alerts-*"


def query_alert_counts(base_url: str, hours: int) -> dict[str, int]:
    """
    Run an aggregation query against OpenSearch to count alerts per rule ID.
    Returns a dict of {rule_id: count}.
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    query = {
        "size": 0,
        "query": {
            "range": {"timestamp": {"gte": since}}
        },
        "aggs": {
            "by_rule": {
                "terms": {
                    "field": "rule.id",
                    "size": 200,
                    "order": {"_count": "desc"},
                }
            }
        },
    }

    try:
        resp = requests.post(
            f"{base_url}/{WAZUH_INDEX}/_search",
            json=query,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        buckets = resp.json()["aggregations"]["by_rule"]["buckets"]
        return {b["key"]: b["doc_count"] for b in buckets}
    except requests.RequestException as e:
        print(f"OpenSearch query failed: {e}", file=sys.stderr)
        return {}


# Rule metadata for display — rule ID → (name, expected_volume)
# expected_volume: "low" / "medium" / "high" based on normal env activity
RULE_META = {
    "100100": ("SSH failed login (single)",     "high"),
    "100101": ("SSH brute force (5+ attempts)", "medium"),
    "100102": ("SSH brute force (sustained)",   "low"),
    "100103": ("SSH attempt on root account",   "medium"),
    "100110": ("Sudo to root",                  "medium"),
    "100111": ("Sudo shell spawn as root",      "low"),
    "100112": ("Repeated sudo failures",        "low"),
    "100200": ("Internal SSH lateral movement", "low"),
    "100202": ("RDP logon",                     "medium"),
    "100203": ("RDP from external IP",          "low"),
    "100300": ("Crontab modified",              "low"),
    "100301": ("System cron file modified",     "low"),
    "100310": ("New user account created",      "low"),
    "100311": ("User added to privileged group","low"),
    "100320": ("authorized_keys modified",      "low"),
    "100321": ("sudoers modified",              "low"),
    "100400": ("Log file deleted",              "low"),
    "100401": ("Log truncated via command",     "low"),
    "100402": ("Auditd stopped",                "low"),
    "100403": ("Firewall disabled",             "low"),
    "100410": ("Rootkit tool flagged",          "low"),
    "100411": ("System binary modified",        "low"),
    "100420": ("Kernel module from /tmp",       "low"),
    "100500": ("Archive in /tmp",               "low"),
    "100501": ("Outbound HTTP POST with data",  "low"),
    "100502": ("Long DNS query (tunneling?)",   "low"),
    "100600": ("Scanning tool executed",        "low"),
    "100601": ("Port scan detected",            "low"),
    "100602": ("AWS metadata accessed",         "low"),
    "100603": ("Sys enum as root",              "low"),
}


def main():
    parser = argparse.ArgumentParser(description="Analyze Wazuh rule alert volume")
    parser.add_argument("--opensearch", default=OPENSEARCH_URL)
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--threshold-high", type=int, default=50,
                        help="Flag rules with more than N alerts as noisy")
    parser.add_argument("--threshold-low", type=int, default=0,
                        help="Flag rules with exactly N alerts as possibly broken")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    print(f"Querying alert counts for last {args.hours}h from {args.opensearch}...")
    counts = query_alert_counts(args.opensearch, args.hours)

    if not counts:
        print("No data returned. Is OpenSearch/Wazuh running?")
        print("Showing expected rule list with zero counts instead.\n")
        counts = {}

    results = []
    for rule_id, (name, expected) in sorted(RULE_META.items()):
        count = counts.get(rule_id, 0)
        flags = []

        if count > args.threshold_high and expected == "low":
            flags.append("NOISY — consider raising frequency/timeframe threshold")
        if count == args.threshold_low and rule_id in counts:
            flags.append("SILENT — verify rule is deployed and pattern matches")
        if rule_id not in counts and count == 0:
            flags.append("NOT SEEN — may not be deployed or no matching events yet")

        results.append({
            "rule_id": rule_id,
            "name": name,
            "count": count,
            "expected_volume": expected,
            "flags": flags,
        })

    if args.json:
        print(json.dumps(results, indent=2))
        return

    print(f"\n{'Rule ID':<12} {'Count':>6}  {'Name':<42} {'Flags'}")
    print("-" * 100)
    for r in results:
        flag_str = " | ".join(r["flags"]) if r["flags"] else "OK"
        flag_color = "\033[33m" if r["flags"] else "\033[32m"
        reset = "\033[0m"
        print(f"{r['rule_id']:<12} {r['count']:>6}  {r['name']:<42} {flag_color}{flag_str}{reset}")

    noisy = [r for r in results if any("NOISY" in f for f in r["flags"])]
    silent = [r for r in results if any("SILENT" in f for f in r["flags"])]

    print(f"\nSummary:")
    print(f"  Total rules tracked: {len(results)}")
    print(f"  Rules flagged noisy: {len(noisy)}")
    print(f"  Rules flagged silent/missing: {len(silent)}")
    print(f"  Total alerts in window: {sum(counts.values())}")


if __name__ == "__main__":
    main()
