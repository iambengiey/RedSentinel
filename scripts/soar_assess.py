#!/usr/bin/env python3
"""
SOAR Threat Assessment
- Pulls telemetry from Dynatrace and Grafana
- Scores each finding using the ML model
- Writes findings JSON for soar_remediate.py
"""
import os, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scripts.pull_from_dynatrace import fetch_dynatrace_problems
from scripts.pull_from_grafana import fetch_grafana_alerts
from models.scorer import score_findings

OUTPUT = Path("data/findings.json")

def main():
    findings = []

    # Dynatrace problems
    dt_url   = os.environ.get("DYNATRACE_URL", "")
    dt_token = os.environ.get("DYNATRACE_TOKEN", "")
    if dt_url and dt_token:
        problems = fetch_dynatrace_problems(dt_url, dt_token)
        findings.extend(problems)
    else:
        print("[SOAR] DYNATRACE_URL/TOKEN not set, skipping")

    # Grafana alerts
    gf_url   = os.environ.get("GRAFANA_URL", "")
    gf_token = os.environ.get("GRAFANA_TOKEN", "")
    if gf_url and gf_token:
        alerts = fetch_grafana_alerts(gf_url, gf_token)
        findings.extend(alerts)
    else:
        print("[SOAR] GRAFANA_URL/TOKEN not set, skipping")

    # Score findings with ML model
    scored = score_findings(findings)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(scored, indent=2))
    print(f"[SOAR] Assessment complete. {len(scored)} findings written to {OUTPUT}")

    critical = [f for f in scored if f.get("severity") in ("CRITICAL", "HIGH")]
    if critical:
        print(f"[SOAR] WARNING: {len(critical)} HIGH/CRITICAL findings require remediation")
        sys.exit(2)   # non-zero triggers remediation step

if __name__ == "__main__":
    main()
