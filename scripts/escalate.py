#!/usr/bin/env python3
"""
Escalation: findings that could not be auto-remediated go to PagerDuty + Jira.
Only fires when data/remediation_log.json has MANUAL_REVIEW entries.
"""
import json, os, sys
from pathlib import Path
from datetime import datetime
try:
    import requests
except ImportError:
    requests = None  # type: ignore

REMED_LOG     = Path("data/remediation_log.json")
PD_KEY        = os.environ.get("PAGERDUTY_KEY", "")
JIRA_URL      = os.environ.get("JIRA_URL", "")
JIRA_USER     = os.environ.get("JIRA_USER", "")
JIRA_TOKEN    = os.environ.get("JIRA_TOKEN", "")
JIRA_PROJECT  = os.environ.get("JIRA_PROJECT", "")
RUNNER_NAME   = os.environ.get("RUNNER_NAME", "unknown-host")

def pagerduty_alert(finding: dict):
    if not PD_KEY or requests is None:
        print("[Escalate] PagerDuty not configured")
        return
    payload = {
        "routing_key":  PD_KEY,
        "event_action": "trigger",
        "payload": {
            "summary":   f"[RedSentinel] {finding.get('type')} on {RUNNER_NAME}",
            "severity":  finding.get("severity", "high").lower(),
            "source":    RUNNER_NAME,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "custom_details": finding,
        },
    }
    resp = requests.post("https://events.pagerduty.com/v2/enqueue",
                         json=payload, timeout=15)
    if resp.status_code == 202:
        print(f"[Escalate] PagerDuty alert sent for {finding.get('type')}")
    else:
        print(f"[Escalate] PagerDuty error {resp.status_code}: {resp.text}")

def jira_ticket(finding: dict):
    if not all([JIRA_URL, JIRA_USER, JIRA_TOKEN, JIRA_PROJECT]) or requests is None:
        print("[Escalate] Jira not configured")
        return
    data = {
        "fields": {
            "project":     {"key": JIRA_PROJECT},
            "summary":     f"[RedSentinel] {finding.get('type')} on {RUNNER_NAME} – manual review required",
            "description": {
                "type": "doc", "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text",
                                 "text": json.dumps(finding, indent=2)}]
                }]
            },
            "issuetype":   {"name": "Bug"},
            "priority":    {"name": "High" if finding.get("severity") == "HIGH" else "Highest"},
            "labels":      ["security", "redsentinel", "manual-review"],
        }
    }
    resp = requests.post(
        f"{JIRA_URL}/rest/api/3/issue",
        json=data,
        auth=(JIRA_USER, JIRA_TOKEN),
        timeout=15,
    )
    if resp.status_code == 201:
        key = resp.json().get("key")
        print(f"[Escalate] Jira ticket created: {JIRA_URL}/browse/{key}")
    else:
        print(f"[Escalate] Jira error {resp.status_code}: {resp.text}")

def main():
    if not REMED_LOG.exists():
        print("[Escalate] No remediation log found")
        sys.exit(0)

    log = json.loads(REMED_LOG.read_text())
    manual = [e for e in log if e.get("action_taken") == "MANUAL_REVIEW"]

    if not manual:
        print("[Escalate] No manual review items, nothing to escalate")
        sys.exit(0)

    print(f"[Escalate] Escalating {len(manual)} items to PagerDuty + Jira")
    for entry in manual:
        finding = entry.get("finding", {})
        pagerduty_alert(finding)
        jira_ticket(finding)

if __name__ == "__main__":
    main()
