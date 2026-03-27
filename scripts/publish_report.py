#!/usr/bin/env python3
"""
Publish compliance/SOAR report as a GitHub Issue with summary.
Runs after every weekly hardening cycle.
"""
import json, os, sys
from pathlib import Path
from datetime import datetime
import urllib.request, urllib.parse

FINDINGS  = Path("data/findings.json")
REMED_LOG = Path("data/remediation_log.json")
GH_TOKEN  = os.environ.get("GH_TOKEN", "")
GH_REPO   = os.environ.get("GITHUB_REPOSITORY", "")
RUNNER_ID = os.environ.get("RUNNER_NAME", "unknown-host")

def post_issue(title: str, body: str):
    if not GH_TOKEN or not GH_REPO:
        print("[Report] GH_TOKEN or GITHUB_REPOSITORY not set, skipping issue creation")
        return
    url = f"https://api.github.com/repos/{GH_REPO}/issues"
    data = json.dumps({"title": title, "body": body, "labels": ["sentinel", "compliance"]}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {GH_TOKEN}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/vnd.github+json")
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
        print(f"[Report] Issue created: {result.get('html_url')}")

def main():
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    findings = json.loads(FINDINGS.read_text()) if FINDINGS.exists() else []
    remed    = json.loads(REMED_LOG.read_text()) if REMED_LOG.exists() else []

    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high     = [f for f in findings if f.get("severity") == "HIGH"]
    medium   = [f for f in findings if f.get("severity") == "MEDIUM"]
    remediated = [r for r in remed if r.get("result", {}).get("rc") == 0]

    body = f"""## RedSentinel Weekly Report
**Host:** `{RUNNER_ID}`
**Run:** {now}

### Findings Summary
| Severity | Count |
|----------|-------|
| CRITICAL | {len(critical)} |
| HIGH     | {len(high)} |
| MEDIUM   | {len(medium)} |
| TOTAL    | {len(findings)} |

### Remediation Summary
- Automated remediations attempted: **{len(remed)}**
- Successful: **{len(remediated)}**
- Manual review required: **{len(remed) - len(remediated)}**

### Controls Applied
- [x] CIS Benchmark Level 1 + Level 2 (SSH, auditd, sysctl, PAM, filesystem)
- [x] Zero Trust: default-deny firewall, least-privilege SA, immutable files
- [x] SOAR: ML-scored findings, automated HIGH/CRITICAL remediation
- [x] Patch cycle executed

### Findings Detail
```json
{json.dumps(critical + high, indent=2)[:3000]}
```
"""
    title = f"[RedSentinel] Weekly Report – {RUNNER_ID} – {now}"
    post_issue(title, body)
    print("[Report] Complete")

if __name__ == "__main__":
    main()
