#!/usr/bin/env python3
"""
SOAR Auto-Remediation
- Reads findings from soar_assess.py output
- Takes automated action for HIGH/CRITICAL findings
- Authenticated via service account key (SENTINEL_SA_KEY secret)
"""
import json, os, subprocess, sys
from pathlib import Path
from datetime import datetime

FINDINGS = Path("data/findings.json")
REMED_LOG = Path("data/remediation_log.json")

REMED_ACTIONS = {
    "SSH_BRUTE_FORCE":    ["bash", "-c", "fail2ban-client set sshd banip {src_ip}"],
    "OPEN_PORT":          ["bash", "scripts/zero_trust.sh"],   # re-apply firewall
    "WORLD_WRITABLE_FILE":["bash", "-c", "chmod o-w {path}"],
    "SUID_BINARY":        ["bash", "-c", "chmod u-s {path}"],
    "UNPATCHED_CVE":      ["bash", "scripts/cis_harden.sh"],   # re-run patching
    "MALICIOUS_PROCESS":  ["bash", "-c", "kill -9 {pid}"],
    "CIS_DRIFT":          ["bash", "scripts/cis_harden.sh"],
}

def run_action(cmd: list, ctx: dict) -> dict:
    """Interpolate context into command args and execute."""
    resolved = [a.format(**ctx) for a in cmd]
    result = subprocess.run(resolved, capture_output=True, text=True, timeout=120)
    return {
        "cmd": resolved,
        "rc":  result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }

def main():
    if not FINDINGS.exists():
        print("[SOAR Remediate] No findings file found, nothing to do.")
        sys.exit(0)

    findings = json.loads(FINDINGS.read_text())
    actionable = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]

    if not actionable:
        print("[SOAR Remediate] No HIGH/CRITICAL findings, nothing to remediate.")
        sys.exit(0)

    print(f"[SOAR Remediate] Processing {len(actionable)} findings")
    log = []

    for finding in actionable:
        ftype = finding.get("type", "UNKNOWN")
        action = REMED_ACTIONS.get(ftype)
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "finding": finding,
            "action_taken": None,
            "result": None,
        }
        if action:
            print(f"  -> Remediating {ftype}")
            entry["action_taken"] = action
            entry["result"] = run_action(action, finding)
        else:
            print(f"  -> No automated action for {ftype}, flagged for human review")
            entry["action_taken"] = "MANUAL_REVIEW"

        log.append(entry)

    REMED_LOG.write_text(json.dumps(log, indent=2))
    print(f"[SOAR Remediate] Done. Log: {REMED_LOG}")

if __name__ == "__main__":
    main()
