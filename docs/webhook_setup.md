# Setting Up Event-Driven Webhooks

RedSentinel supports **sub-minute response** for CRITICAL findings by accepting
`workflow_dispatch` webhooks from Dynatrace, Grafana, and Wazuh.

---

## GitHub Webhook URL

```
POST https://api.github.com/repos/iambengiey/RedSentinel/actions/workflows/sentinel-weekly.yml/dispatches
```

**Headers:**
```
Authorization: Bearer <GH_TOKEN with workflow scope>
Content-Type: application/json
Accept: application/vnd.github+json
```

**Body:**
```json
{
  "ref": "main",
  "inputs": {
    "finding_type": "SSH_BRUTE_FORCE",
    "src_ip": "1.2.3.4",
    "severity": "CRITICAL",
    "skip_hardening": "true"
  }
}
```

> Set `skip_hardening: true` for event-driven calls so only assess + remediate runs,
> not full CIS/ZT re-hardening.

---

## Dynatrace – Problem Notification

1. Go to **Settings → Integrations → Problem notifications**
2. Add a **Custom integration** webhook
3. URL: `https://api.github.com/repos/iambengiey/RedSentinel/actions/workflows/sentinel-weekly.yml/dispatches`
4. Headers: `Authorization: Bearer <GH_TOKEN>`, `Accept: application/vnd.github+json`
5. Body (use Dynatrace placeholders):
```json
{
  "ref": "main",
  "inputs": {
    "finding_type": "{ProblemTitle}",
    "src_ip": "",
    "severity": "{ProblemSeverity}",
    "skip_hardening": "true"
  }
}
```

---

## Grafana – Contact Point

1. Go to **Alerting → Contact points → New contact point**
2. Type: **Webhook**
3. URL: same as above
4. Message body:
```json
{
  "ref": "main",
  "inputs": {
    "finding_type": "{{ .CommonLabels.alertname }}",
    "src_ip": "{{ .CommonAnnotations.src_ip }}",
    "severity": "{{ .CommonLabels.severity }}",
    "skip_hardening": "true"
  }
}
```
5. Assign to your alert routing policy for `severity=critical`

---

## Wazuh – Active Response + Webhook

Wazuh has its own active-response engine but can also fire webhooks.

### Option A: Wazuh Active Response (fastest – runs on-agent)
Add to `/var/ossec/etc/ossec.conf`:
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5710,5711,5712</rules_id>  <!-- SSH brute force rules -->
  <timeout>600</timeout>
</active-response>
```
This blocks the IP **directly on the agent** within milliseconds – before GHA even starts.

### Option B: Wazuh → GitHub webhook (for audit trail)
1. Install `wazuh-integrations` and configure a custom integration:
```xml
<integration>
  <name>custom-github</name>
  <hook_url>https://api.github.com/repos/iambengiey/RedSentinel/actions/workflows/sentinel-weekly.yml/dispatches</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```
2. Create a custom script at `/var/ossec/integrations/custom-github` that
   transforms the Wazuh alert JSON into the GHA `workflow_dispatch` payload format.

---

## Escalation Secrets Required

| Secret | Purpose |
|--------|---------|
| `PAGERDUTY_KEY` | PagerDuty Events API v2 routing key |
| `JIRA_URL` | Jira base URL (e.g. `https://yourorg.atlassian.net`) |
| `JIRA_USER` | Jira account email |
| `JIRA_TOKEN` | Jira API token |
| `JIRA_PROJECT` | Jira project key (e.g. `SEC`) |
| `WAZUH_URL` | Wazuh Manager API URL (e.g. `https://wazuh.internal:55000`) |
| `WAZUH_USER` | Wazuh API user |
| `WAZUH_PASS` | Wazuh API password |
