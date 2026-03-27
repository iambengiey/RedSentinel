#!/usr/bin/env python3
"""
Pull firing alerts from Grafana Alerting API
"""
import os, json
from typing import List, Dict, Any
try:
    import requests
except ImportError:
    requests = None  # type: ignore

def fetch_grafana_alerts(base_url: str, token: str) -> List[Dict[str, Any]]:
    if requests is None:
        raise RuntimeError("requests library not installed")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }
    url = f"{base_url.rstrip('/')}/api/alertmanager/grafana/api/v2/alerts"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    alerts = resp.json()

    findings = []
    for a in alerts:
        labels   = a.get("labels", {})
        severity = labels.get("severity", "LOW").upper()
        findings.append({
            "source":   "grafana",
            "id":       a.get("fingerprint"),
            "type":     _map_grafana_type(labels),
            "title":    labels.get("alertname", "Unknown"),
            "severity": severity,
            "status":   a.get("status", {}).get("state", "unknown"),
            "raw":      a,
        })
    return findings

def _map_grafana_type(labels: dict) -> str:
    name = labels.get("alertname", "").lower()
    if "ssh" in name:                     return "SSH_BRUTE_FORCE"
    if "port" in name:                    return "OPEN_PORT"
    if "suid" in name:                    return "SUID_BINARY"
    if "writable" in name or "perm" in name: return "WORLD_WRITABLE_FILE"
    if "cve" in name or "patch" in name:  return "UNPATCHED_CVE"
    if "cis" in name or "drift" in name:  return "CIS_DRIFT"
    return "ANOMALOUS_TRAFFIC"
