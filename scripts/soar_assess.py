#!/usr/bin/env python3
"""
SOAR Threat Assessment
- Pulls from Dynatrace, Grafana, and Wazuh
- Injects event-driven findings from workflow_dispatch inputs
- Scores each finding via ML model
- Writes data/findings.json
"""
import os, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scripts.pull_from_dynatrace import fetch_dynatrace_problems
from scripts.pull_from_grafana import fetch_grafana_alerts
from scripts.pull_from_wazuh import fetch_wazuh_alerts
from models.scorer import score_findings

OUTPUT = Path("data/findings.json")

def inject_event_finding(findings: list):
    """If triggered via workflow_dispatch, inject the webhook finding directly."""
    ftype    = os.environ.get("EVENT_FINDING_TYPE", "").strip()
    src_ip   = os.environ.get("EVENT_SRC_IP", "").strip()
    severity = os.environ.get("EVENT_SEVERITY", "").strip().upper()
    if ftype:
        findings.append({
            "source":   "webhook",
            "id":       f"event-{ftype}-{src_ip}",
            "type":     ftype,
            "title":    f"Event-driven: {ftype}",
            "severity": severity or "HIGH",
            "src_ip":   src_ip,
        })
        print(f"[SOAR] Injected event-driven finding: {ftype} src={src_ip} sev={severity}")

def main():
    findings = []

    # Dynatrace
    dt_url, dt_token = os.environ.get("DYNATRACE_URL", ""), os.environ.get("DYNATRACE_TOKEN", "")
    if dt_url and dt_token:
        findings.extend(fetch_dynatrace_problems(dt_url, dt_token))
    else:
        print("[SOAR] Dynatrace not configured, skipping")

    # Grafana
    gf_url, gf_token = os.environ.get("GRAFANA_URL", ""), os.environ.get("GRAFANA_TOKEN", "")
    if gf_url and gf_token:
        findings.extend(fetch_grafana_alerts(gf_url, gf_token))
    else:
        print("[SOAR] Grafana not configured, skipping")

    # Wazuh
    wz_url  = os.environ.get("WAZUH_URL", "")
    wz_user = os.environ.get("WAZUH_USER", "")
    wz_pass = os.environ.get("WAZUH_PASS", "")
    if wz_url and wz_user:
        findings.extend(fetch_wazuh_alerts(wz_url, wz_user, wz_pass))
    else:
        print("[SOAR] Wazuh not configured, skipping")

    # Event-driven injection (workflow_dispatch)
    inject_event_finding(findings)

    scored = score_findings(findings)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(scored, indent=2))
    print(f"[SOAR] {len(scored)} findings scored -> {OUTPUT}")

    critical = [f for f in scored if f.get("severity") in ("CRITICAL", "HIGH")]
    if critical:
        print(f"[SOAR] {len(critical)} HIGH/CRITICAL findings need remediation")
        sys.exit(2)

if __name__ == "__main__":
    main()
