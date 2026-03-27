#!/usr/bin/env python3
"""
Runner Health Monitor – runs on GitHub-hosted ubuntu-latest (schedule only).
Checks all self-hosted runners for the repo; alerts via PagerDuty if any are offline.
"""
import json, os, sys
from datetime import datetime, timezone
try:
    import requests
except ImportError:
    requests = None  # type: ignore

GH_TOKEN  = os.environ.get("GH_TOKEN", "")
GH_REPO   = os.environ.get("GITHUB_REPOSITORY", "")
PD_KEY    = os.environ.get("PAGERDUTY_KEY", "")

def get_runners() -> list:
    if requests is None or not GH_TOKEN or not GH_REPO:
        print("[Health] GH_TOKEN or GITHUB_REPOSITORY not set")
        return []
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    resp = requests.get(
        f"https://api.github.com/repos/{GH_REPO}/actions/runners",
        headers=headers,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json().get("runners", [])

def alert_pagerduty(runner_name: str, status: str):
    if not PD_KEY or requests is None:
        print(f"[Health] PagerDuty not configured – offline runner: {runner_name}")
        return
    payload = {
        "routing_key":  PD_KEY,
        "event_action": "trigger",
        "payload": {
            "summary":   f"[RedSentinel] Runner OFFLINE: {runner_name}",
            "severity":  "critical",
            "source":    "runner-health-monitor",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "custom_details": {"runner": runner_name, "status": status},
        },
    }
    resp = requests.post("https://events.pagerduty.com/v2/enqueue",
                         json=payload, timeout=15)
    print(f"[Health] PagerDuty alert for {runner_name}: {resp.status_code}")

def main():
    runners = get_runners()
    if not runners:
        print("[Health] No runners found or API error")
        sys.exit(0)

    offline = [r for r in runners if r.get("status") != "online"]
    print(f"[Health] {len(runners)} runners total, {len(offline)} offline")

    for r in offline:
        name   = r.get("name", "unknown")
        status = r.get("status", "unknown")
        print(f"  [OFFLINE] {name} – status: {status}")
        alert_pagerduty(name, status)

    if offline:
        sys.exit(1)  # Fail the job so it's visible in GHA

if __name__ == "__main__":
    main()
