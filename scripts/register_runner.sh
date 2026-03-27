#!/usr/bin/env bash
# Register this host as a self-hosted GitHub Actions runner
# Run ONCE per host with: sudo bash scripts/register_runner.sh <GH_PAT> <RUNNER_LABEL>
# The PAT only needs repo scope (or org scope for org runners)
set -euo pipefail

GH_REPO="${1:-iambengiey/RedSentinel}"   # override via env or arg
GH_TOKEN="${2:-}"                        # GitHub PAT
RUNNER_LABEL="${3:-$(hostname -s)}"      # default label = hostname
RUNNER_VERSION="2.314.1"
RUNNER_DIR="/opt/actions-runner"
RUNNER_USER="sentinel-sa"

if [ -z "$GH_TOKEN" ]; then
  echo "Usage: $0 <owner/repo> <GH_PAT> [runner-label]"
  exit 1
fi

# Detect arch
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  RUNNER_ARCH="x64"   ;;
  aarch64) RUNNER_ARCH="arm64" ;;
  *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

# Download runner
RUNNER_PKG="actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz"
if [ ! -f "$RUNNER_PKG" ]; then
  curl -fLo "$RUNNER_PKG" \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_PKG}"
fi
tar xzf "$RUNNER_PKG"

# Get registration token
REG_TOKEN=$(curl -fsSL \
  -X POST \
  -H "Authorization: Bearer $GH_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${GH_REPO}/actions/runners/registration-token" \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# Configure
sudo -u "$RUNNER_USER" ./config.sh \
  --url "https://github.com/${GH_REPO}" \
  --token "$REG_TOKEN" \
  --name "$(hostname -s)" \
  --labels "self-hosted,${RUNNER_LABEL},${OS_FAMILY:-linux}" \
  --unattended

# Install as systemd service
./svc.sh install "$RUNNER_USER"
./svc.sh start

echo "Runner registered and started: $(hostname -s) -> $GH_REPO"
