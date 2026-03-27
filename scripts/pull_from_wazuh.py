#!/usr/bin/env python3
"""
Pull active alerts from Wazuh Manager REST API (v4+)
Wazuh provides real-time HIDS alerts including CIS checks, rootkit detection,
SSH brute-force, file integrity monitoring (FIM), and anomaly detection.
"""
import json
from typing import List, Dict, Any
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # Wazuh often uses self-signed cert
except ImportError:
    requests = None  # type: ignore

# Wazuh rule level thresholds
LEVEL_TO_SEVERITY = {
    range(0, 4):   "LOW",
    range(4, 8):   "MEDIUM",
    range(8, 12):  "HIGH",
    range(12, 16): "CRITICAL",
}

WAZUH_TYPE_MAP = {
    "sshd":             "SSH_BRUTE_FORCE",
    "syscheck":         "WORLD_WRITABLE_FILE",
    "rootcheck":        "SUID_BINARY",
    "vulnerability":    "UNPATCHED_CVE",
    "ciscat":           "CIS_DRIFT",
    "anomaly":          "ANOMALOUS_TRAFFIC",
}

def _level_to_severity(level: int) -> str:
    for r, sev in LEVEL_TO_SEVERITY.items():
        if level in r:
            return sev
    return "LOW"

def _get_token(base_url: str, user: str, password: str) -> str:
    if requests is None:
        raise RuntimeError("requests not installed")
    resp = requests.post(
        f"{base_url}/security/user/authenticate",
        auth=(user, password),
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["data"]["token"]

def fetch_wazuh_alerts(base_url: str, user: str, password: str,
                       min_level: int = 7, limit: int = 50) -> List[Dict[str, Any]]:
    if requests is None:
        raise RuntimeError("requests not installed")

    token = _get_token(base_url, user, password)
    headers = {"Authorization": f"Bearer {token}"}
    params = {"level": f"{min_level}-15", "limit": limit, "sort": "-timestamp"}
    resp = requests.get(
        f"{base_url}/alerts",
        headers=headers,
        params=params,
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    alerts = resp.json().get("data", {}).get("affected_items", [])

    findings = []
    for a in alerts:
        rule    = a.get("rule", {})
        level   = rule.get("level", 0)
        decoder = a.get("decoder", {}).get("name", "unknown")
        ftype   = next((v for k, v in WAZUH_TYPE_MAP.items() if k in decoder.lower()),
                       "ANOMALOUS_TRAFFIC")
        findings.append({
            "source":   "wazuh",
            "id":       a.get("id"),
            "type":     ftype,
            "title":    rule.get("description", "Wazuh alert"),
            "severity": _level_to_severity(level),
            "level":    level,
            "agent":    a.get("agent", {}).get("name"),
            "src_ip":   a.get("data", {}).get("srcip", ""),
            "path":     a.get("syscheck", {}).get("path", ""),
            "pid":      a.get("data", {}).get("pid", ""),
            "raw":      a,
        })
    return findings
