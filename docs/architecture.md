# RedSentinel Architecture

## Overview

RedSentinel applies **SOAR + Zero Trust + CIS Benchmarks** to SLES and RHEL hosts
running on any platform (bare metal, VMware/XEN, ARM, x64). Instead of a central
Ansible controller, **each host is its own GitHub Actions self-hosted runner**,
executing the weekly workflow independently and publishing results back to GitHub.

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Zero Trust** | Default-deny nftables/firewalld, no root SSH, SA key-only auth, least-privilege sudo |
| **SOAR** | ML-scored findings → automated remediation → GH Issue report |
| **CIS Benchmarks** | Level 1+2: SSH, auditd, sysctl, PAM, filesystem, patching |
| **Platform-agnostic** | `detect_os.sh` branches on `OS_FAMILY` (sles/rhel); x64 + ARM64 |
| **No central controller** | Each host = its own GHA runner; no Ansible master needed |

## Execution Flow

```
[Monday 02:00 UTC]
  |
  v
GitHub Actions Scheduler
  |
  +-- [Each host runner in parallel] -->
        |
        +-- detect_os.sh         # Identify SLES vs RHEL, arch
        +-- cis_harden.sh        # Apply CIS L1+L2 controls
        +-- zero_trust.sh        # Firewall, SA key, least-priv
        +-- soar_assess.py       # Pull Dynatrace/Grafana, ML score
        +-- soar_remediate.py    # Auto-fix HIGH/CRITICAL findings
        +-- publish_report.py    # Post GitHub Issue with results
```

## Authentication

- The `sentinel-sa` OS service account is created on each host
- Its **public SSH key** is stored as the `SENTINEL_SA_KEY` GitHub Actions secret
- `zero_trust.sh` writes the public key to `~sentinel-sa/.ssh/authorized_keys`
- The GHA runner itself runs as `sentinel-sa` with scoped sudo

## Secrets Required (GitHub Repository Secrets)

| Secret | Purpose |
|--------|---------|
| `SENTINEL_SA_KEY` | SSH public key for `sentinel-sa` service account |
| `DYNATRACE_TOKEN` | Dynatrace API token (read problems) |
| `DYNATRACE_URL`   | Dynatrace environment base URL |
| `GRAFANA_TOKEN`   | Grafana service account token (read alerts) |
| `GRAFANA_URL`     | Grafana instance base URL |
| `GH_TOKEN`        | GitHub PAT with `issues:write` for report publishing |

## Adding a New Host

1. Provision host (SLES or RHEL, any platform)
2. Create `sentinel-sa` user and ensure internet access to `github.com`
3. Run: `sudo bash scripts/register_runner.sh iambengiey/RedSentinel <GH_PAT> <hostname>`
4. Host will self-register as a runner and execute every Monday

## CIS Controls Covered

- **1.x** – Filesystem hardening (cramfs/hfs disabled, /tmp hardened)
- **1.8** – Patching (dnf/zypper security updates)
- **3.x** – Network kernel parameters (sysctl hardening)
- **4.x** – Auditd logging (time, identity, sudo, mounts)
- **5.x** – SSH hardening, PAM password policy
- **Zero Trust addons** – nftables default-deny, cron restriction, chattr immutability
