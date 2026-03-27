# RedSentinel Architecture

## Overview

RedSentinel applies **SOAR + Zero Trust + CIS Benchmarks** to SLES and RHEL hosts
running on any platform (bare metal, VMware/XEN, ARM, x64). Each host is its own
GitHub Actions self-hosted runner. The system supports both **scheduled weekly hardening**
and **event-driven sub-minute response** via webhooks.

---

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Zero Trust** | Default-deny nftables, no root SSH, SA key-only auth, least-privilege sudo, chattr immutable |
| **SOAR** | ML-scored findings → automated remediation → escalation → GH Issue report |
| **CIS Benchmarks** | Level 1+2: SSH, auditd, sysctl, PAM, filesystem, patching |
| **Event-driven** | Webhooks from Dynatrace/Grafana/Wazuh trigger immediate response (< 60s) |
| **Platform-agnostic** | `detect_os.sh` on SLES/RHEL, x64/ARM64, any hypervisor |
| **No central controller** | Each host = its own GHA runner; no Ansible master |

---

## Execution Flow

### Scheduled (Weekly)
```
Monday 02:00 UTC
  └── [All self-hosted runners in parallel]
        ├── detect_os.sh         # SLES vs RHEL, arch
        ├── cis_harden.sh        # CIS L1+L2
        ├── zero_trust.sh        # firewall, SA key, least-priv
        ├── soar_assess.py       # Dynatrace + Grafana + Wazuh → ML score
        ├── soar_remediate.py    # auto-fix HIGH/CRITICAL
        ├── escalate.py          # PagerDuty + Jira for MANUAL_REVIEW items
        └── publish_report.py    # GitHub Issue report

  └── [GitHub-hosted runner]
        └── runner_health.py     # check all hosts online, alert if not
```

### Event-Driven (webhook)
```
Dynatrace/Grafana/Wazuh CRITICAL alert
  └── POST workflow_dispatch → GitHub API
        └── [Affected self-hosted runner]
              ├── soar_immediate.py    # instant IP ban / process kill
              ├── soar_assess.py       # full assessment with injected finding
              ├── soar_remediate.py    # remediate all HIGH/CRITICAL
              ├── escalate.py          # PagerDuty + Jira
              └── publish_report.py    # report with trigger=webhook
```

---

## Authentication Model

| Component | Auth Method |
|-----------|------------|
| GHA Runner → host OS | `sentinel-sa` service account, SSH public key only |
| Dynatrace API | API Token (secret) |
| Grafana API | Service account Bearer token (secret) |
| Wazuh API | Username + password (secrets), JWT internally |
| PagerDuty | Events API v2 routing key |
| Jira | Email + API token (Basic auth) |
| GitHub Issues | PAT with `issues:write` + `actions:write` |

---

## Secrets Reference

| Secret | Purpose |
|--------|---------|
| `SENTINEL_SA_KEY` | SSH public key for `sentinel-sa` OS account |
| `DYNATRACE_TOKEN` | Dynatrace API token |
| `DYNATRACE_URL` | Dynatrace environment URL |
| `GRAFANA_TOKEN` | Grafana service account token |
| `GRAFANA_URL` | Grafana instance URL |
| `WAZUH_URL` | Wazuh Manager API URL |
| `WAZUH_USER` | Wazuh API username |
| `WAZUH_PASS` | Wazuh API password |
| `PAGERDUTY_KEY` | PagerDuty Events API v2 routing key |
| `JIRA_URL` | Jira base URL |
| `JIRA_USER` | Jira account email |
| `JIRA_TOKEN` | Jira API token |
| `JIRA_PROJECT` | Jira project key |
| `GH_TOKEN` | PAT: `issues:write` + `actions:write` |

---

## Adding a New Host

1. Provision host (SLES or RHEL, any platform)
2. Ensure `sentinel-sa` user and internet access to `github.com`
3. Run: `sudo bash scripts/register_runner.sh iambengiey/RedSentinel <GH_PAT> <hostname>`
4. Host self-registers, executes every Monday, and responds to webhooks within ~60s
