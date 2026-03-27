#!/usr/bin/env bash
# Zero Trust controls: least-privilege, network segmentation, mTLS readiness
# Authenticates using service account SSH key stored as GHA secret
set -euo pipefail

echo "==> [ZeroTrust] Applying Zero Trust controls"

# ---- 1. SERVICE ACCOUNT SETUP ---------------------------------------------
SA_USER="sentinel-sa"
SA_HOME="/home/${SA_USER}"
SA_AUTH_KEYS="${SA_HOME}/.ssh/authorized_keys"

if ! id "$SA_USER" &>/dev/null; then
  useradd -m -s /bin/bash -d "$SA_HOME" "$SA_USER"
  echo "Created service account: $SA_USER"
fi

mkdir -p "${SA_HOME}/.ssh"
chmod 700 "${SA_HOME}/.ssh"
chown "${SA_USER}:${SA_USER}" "${SA_HOME}/.ssh"

# Write public key from secret (secret holds the PUBLIC key)
if [ -n "${SENTINEL_SA_KEY:-}" ]; then
  echo "$SENTINEL_SA_KEY" > "$SA_AUTH_KEYS"
  chmod 600 "$SA_AUTH_KEYS"
  chown "${SA_USER}:${SA_USER}" "$SA_AUTH_KEYS"
  echo "[ZeroTrust] Service account SSH key configured"
fi

# ---- 2. SUDO - LEAST PRIVILEGE (NO PASSWORD, SCOPED) ---------------------
echo "[ZeroTrust] Configuring least-privilege sudo"
cat > /etc/sudoers.d/sentinel-sa <<'EOF'
# sentinel-sa may only run remediation scripts, no interactive sudo
sentinel-sa ALL=(root) NOPASSWD: /usr/local/bin/sentinel-remediate.sh
EOF
chmod 440 /etc/sudoers.d/sentinel-sa

# ---- 3. FIREWALL (nftables preferred, fallback firewalld) -----------------
echo "[ZeroTrust] Applying default-deny firewall rules"
if command -v nft &>/dev/null; then
  nft flush ruleset
  nft -f - <<'NFTRULES'
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport 22 accept comment "SSH"
    icmp type echo-request accept
    icmpv6 type { echo-request, nd-neighbor-solicit, nd-router-advert } accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}
NFTRULES
  echo "[ZeroTrust] nftables rules applied"
elif command -v firewall-cmd &>/dev/null; then
  systemctl enable --now firewalld
  firewall-cmd --set-default-zone=drop
  firewall-cmd --zone=drop --add-service=ssh --permanent
  firewall-cmd --reload
  echo "[ZeroTrust] firewalld rules applied"
fi

# ---- 4. DISABLE UNNECESSARY SERVICES -------------------------------------
echo "[ZeroTrust] Disabling unused services"
for svc in telnet rsh rlogin rexec tftp xinetd cups avahi-daemon bluetooth; do
  systemctl disable --now "$svc" 2>/dev/null || true
done

# ---- 5. IMMUTABLE /etc/passwd,shadow (chattr) ----------------------------
echo "[ZeroTrust] Setting immutable flags on critical files"
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
  chattr +i "$f" 2>/dev/null || true
done

# ---- 6. RESTRICT CRON TO ROOT + SENTINEL-SA ONLY -------------------------
echo "[ZeroTrust] Restricting cron access"
echo "root" > /etc/cron.allow
echo "sentinel-sa" >> /etc/cron.allow
rm -f /etc/cron.deny

echo "[ZeroTrust] Controls applied."
