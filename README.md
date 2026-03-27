# RedSentinel

ML-driven SOAR + Zero Trust + CIS Benchmark hardening for **SLES and RHEL** hosts running on any platform (bare metal, VMware/XEN, ARM64, x64). Each host registers as its own GitHub Actions self-hosted runner — no central Ansible controller required.

Supports both **scheduled weekly hardening** (every Monday 02:00 UTC) and **event-driven sub-minute response** via webhooks from Dynatrace, Grafana, and Wazuh.

---

## Structure

- `.github/workflows/` — Weekly + event-driven GHA workflow
- `scripts/` — CIS hardening, Zero Trust controls, SOAR assess/remediate/escalate, runner health
- `models/` — Trained ML models (ONNX, Pickle); rule-based fallback if none present
- `data/` — Runtime findings and remediation logs (gitignored)
- `docs/` — Architecture diagrams, webhook setup guide
- `api/` — FastAPI app for real-time model inference
- `notebooks/` — Jupyter notebooks for model training

---

## Quickstart

### 1. Register a host as a self-hosted runner
Run once per host (SLES or RHEL, any platform):
```bash
sudo bash scripts/register_runner.sh iambengiey/RedSentinel <GH_PAT> <hostname>
```
The host self-registers, executes every Monday, and responds to webhooks within ~60 seconds.

### 2. Configure GitHub Actions Secrets
Go to **Settings → Secrets and variables → Actions** and add the secrets below.

### 3. (Optional) Wire up webhooks
See [`docs/webhook_setup.md`](docs/webhook_setup.md) for step-by-step Dynatrace, Grafana, and Wazuh webhook configuration.

### 4. (Optional) Drop a trained model
Place a `.onnx` or `.pkl` model in `models/` — the scorer auto-loads it. Without one, rule-based scoring is used.

---

## GitHub Actions Secrets

All secrets are optional except `SENTINEL_SA_KEY` and `GH_TOKEN`. Missing secrets cause the relevant step to log a skip and continue cleanly.

### Core (Required)

| Secret | Description |
|--------|-------------|
| `SENTINEL_SA_KEY` | SSH **public key** for the `sentinel-sa` OS service account on each host |
| `GH_TOKEN` | GitHub PAT with `issues:write` and `actions:write` scopes |

### Telemetry — Dynatrace

| Secret | Description |
|--------|-------------|
| `DYNATRACE_URL` | Dynatrace environment base URL (e.g. `https://abc123.live.dynatrace.com`) |
| `DYNATRACE_TOKEN` | Dynatrace API token with `problems:read` scope |

### Telemetry — Grafana

| Secret | Description |
|--------|-------------|
| `GRAFANA_URL` | Grafana instance base URL (e.g. `https://grafana.yourdomain.com`) |
| `GRAFANA_TOKEN` | Grafana service account token with `alerting:read` scope |

### Telemetry — Wazuh (HIDS)

| Secret | Description |
|--------|-------------|
| `WAZUH_URL` | Wazuh Manager API URL (e.g. `https://wazuh.internal:55000`) |
| `WAZUH_USER` | Wazuh API username |
| `WAZUH_PASS` | Wazuh API password |

### Escalation — PagerDuty

| Secret | Description |
|--------|-------------|
| `PAGERDUTY_KEY` | PagerDuty Events API v2 routing key |

### Escalation — Jira

| Secret | Description |
|--------|-------------|
| `JIRA_URL` | Jira base URL (e.g. `https://yourorg.atlassian.net`) |
| `JIRA_USER` | Jira account email address |
| `JIRA_TOKEN` | Jira API token |
| `JIRA_PROJECT` | Jira project key (e.g. `SEC`) |

---

## Execution Flow

### Scheduled (Weekly — every Monday 02:00 UTC)
```
[All self-hosted runners — in parallel]
  detect_os.sh        → identify SLES/RHEL, x64/ARM64
  cis_harden.sh       → CIS Level 1+2 (SSH, auditd, sysctl, PAM, patching)
  zero_trust.sh       → default-deny firewall, SA key, least-priv sudo, chattr
  soar_assess.py      → Dynatrace + Grafana + Wazuh → ML-scored findings
  soar_remediate.py   → auto-fix HIGH/CRITICAL findings
  escalate.py         → PagerDuty + Jira for MANUAL_REVIEW items
  publish_report.py   → GitHub Issue compliance report

[GitHub-hosted runner]
  runner_health.py    → alert PagerDuty if any self-hosted runner is offline
```

### Event-Driven (webhook → sub-minute response)
```
Dynatrace / Grafana / Wazuh CRITICAL alert
  → POST workflow_dispatch to GitHub API
    → soar_immediate.py   → instant IP ban / process kill
    → soar_assess.py      → full assessment with injected finding
    → soar_remediate.py   → remediate all HIGH/CRITICAL
    → escalate.py         → PagerDuty + Jira
    → publish_report.py   → report tagged trigger=webhook
```

---

## CIS Controls Covered

| Section | Controls |
|---------|---------|
| 1.x | Filesystem: cramfs/hfs/udf disabled, `/tmp` noexec/nosuid/nodev |
| 1.8 | Security patching via `dnf --security` / `zypper patch --category security` |
| 3.x | sysctl: IP forwarding, ICMP redirects, SYN cookies, ASLR, martian logging |
| 4.x | auditd: time-change, identity, sudo scope, mount events |
| 5.x | SSH pubkey-only, no root login, no X11/TCP forward; PAM password policy |

---

## Docs

- [`docs/architecture.md`](docs/architecture.md) — full design, auth model, secrets reference
- [`docs/webhook_setup.md`](docs/webhook_setup.md) — Dynatrace, Grafana, Wazuh webhook config
