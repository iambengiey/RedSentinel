#!/usr/bin/env bash
# CIS Benchmark hardening for SLES and RHEL
# Covers CIS Level 1 + Level 2 controls applicable cross-platform
set -euo pipefail

echo "==> [CIS] Starting hardening for OS_FAMILY=${OS_FAMILY:-unknown}"

# ---- 1. FILESYSTEM --------------------------------------------------------
echo "[CIS 1.x] Filesystem hardening"
# Disable unused filesystems
for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
  if ! grep -q "install $fs /bin/true" /etc/modprobe.d/cis_hardened.conf 2>/dev/null; then
    echo "install $fs /bin/true" >> /etc/modprobe.d/cis_hardened.conf
  fi
done

# /tmp noexec, nosuid, nodev
if mountpoint -q /tmp; then
  mount -o remount,noexec,nosuid,nodev /tmp || true
fi

# ---- 2. SOFTWARE UPDATES --------------------------------------------------
echo "[CIS 1.8] Apply security patches"
if [ "${PKG_MGR:-unknown}" = "dnf" ]; then
  dnf -y update --security || true
elif [ "${PKG_MGR:-unknown}" = "zypper" ]; then
  zypper -n patch --category security || true
fi

# ---- 3. SSH HARDENING (CIS 5.x) ------------------------------------------
echo "[CIS 5.x] SSH server hardening"
SSHD=/etc/ssh/sshd_config

declare -A SSH_SETTINGS=(
  ["Protocol"]="2"
  ["LogLevel"]="VERBOSE"
  ["LoginGraceTime"]="60"
  ["PermitRootLogin"]="no"
  ["MaxAuthTries"]="4"
  ["IgnoreRhosts"]="yes"
  ["HostbasedAuthentication"]="no"
  ["PermitEmptyPasswords"]="no"
  ["PermitUserEnvironment"]="no"
  ["ClientAliveInterval"]="300"
  ["ClientAliveCountMax"]="3"
  ["Banner"]="/etc/issue.net"
  ["AllowTcpForwarding"]="no"
  ["X11Forwarding"]="no"
  ["MaxStartups"]="10:30:60"
  ["PubkeyAuthentication"]="yes"
  ["PasswordAuthentication"]="no"
  ["AuthenticationMethods"]="publickey"
)

for key in "${!SSH_SETTINGS[@]}"; do
  val="${SSH_SETTINGS[$key]}"
  if grep -qE "^#?\s*${key}\s" "$SSHD"; then
    sed -i "s|^#\?\s*${key}.*|${key} ${val}|" "$SSHD"
  else
    echo "${key} ${val}" >> "$SSHD"
  fi
done

systemctl restart sshd || true

# ---- 4. AUDITD (CIS 4.x) --------------------------------------------------
echo "[CIS 4.x] Configuring auditd"
if [ "${PKG_MGR:-unknown}" = "dnf" ]; then
  dnf -y install audit audit-libs || true
elif [ "${PKG_MGR:-unknown}" = "zypper" ]; then
  zypper -n install audit || true
fi

cat > /etc/audit/rules.d/cis_sentinel.rules <<'EOF'
# CIS Required audit rules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-e 2
EOF

service auditd restart || systemctl restart auditd || true

# ---- 5. KERNEL PARAMETERS (CIS 3.x) --------------------------------------
echo "[CIS 3.x] Kernel sysctl hardening"
cat > /etc/sysctl.d/99-cis-sentinel.conf <<'EOF'
# Network - disable IP forwarding (unless a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
# Enable SYN cookies
net.ipv4.tcp_syncookies = 1
# Log martians
net.ipv4.conf.all.log_martians = 1
# Randomize memory layout
kernel.randomize_va_space = 2
# Restrict core dumps
fs.suid_dumpable = 0
EOF

sysctl --system

# ---- 6. PAM / PASSWORD POLICY (CIS 5.3.x) --------------------------------
echo "[CIS 5.3.x] Password and account policy"
if [ "${OS_FAMILY:-unknown}" = "rhel" ]; then
  authconfig --passminlen=14 --passminclass=4 --update 2>/dev/null || \
    authselect apply-changes 2>/dev/null || true
elif [ "${OS_FAMILY:-unknown}" = "sles" ]; then
  sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t14/' /etc/login.defs || true
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs || true
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs || true
fi

echo "[CIS] Hardening complete."
