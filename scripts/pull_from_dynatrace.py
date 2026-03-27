#!/usr/bin/env python3
"""
Pull problems/alerts from Dynatrace API v2
"""
import os, json
from typing import List, Dict, Any
try:
    import requests
except ImportError:
    requests = None  # type: ignore

def fetch_dynatrace_problems(base_url: str, token: str) -> List[Dict[str, Any]]:
    if requests is None:
        raise RuntimeError("requests library not installed")

    headers = {
        "Authorization": f"Api-Token {token}",
        "Accept": "application/json; charset=utf-8",
    }
    url = f"{base_url.rstrip('/')}/api/v2/problems"
    params = {"problemSelector": "status(\"OPEN\")", "pageSize": 50}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    problems = resp.json().get("problems", [])

    findings = []
    for p in problems:
        findings.append({
            "source":   "dynatrace",
            "id":       p.get("problemId"),
            "type":     _map_dt_type(p.get("title", "")),
            "title":    p.get("title"),
            "severity": p.get("severityLevel", "LOW"),
            "status":   p.get("status"),
            "raw":      p,
        })
    return findings

def _map_dt_type(title: str) -> str:
    title_lower = title.lower()
    if "ssh" in title_lower or "brute" in title_lower: return "SSH_BRUTE_FORCE"
    if "port" in title_lower:                          return "OPEN_PORT"
    if "malicious" in title_lower or "malware" in title_lower: return "MALICIOUS_PROCESS"
    if "cve" in title_lower:                           return "UNPATCHED_CVE"
    return "ANOMALOUS_TRAFFIC"
