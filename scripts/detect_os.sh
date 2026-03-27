#!/usr/bin/env bash
# Detect OS family and export for subsequent steps
set -euo pipefail

if [ -f /etc/os-release ]; then
  . /etc/os-release
else
  echo "Cannot detect OS" && exit 1
fi

echo "OS_ID=${ID}" >> "$GITHUB_ENV"
echo "OS_VERSION=${VERSION_ID}" >> "$GITHUB_ENV"

case "$ID" in
  sles|opensuse-leap)
    echo "OS_FAMILY=sles" >> "$GITHUB_ENV"
    echo "PKG_MGR=zypper" >> "$GITHUB_ENV"
    ;;
  rhel|centos|rocky|almalinux)
    echo "OS_FAMILY=rhel" >> "$GITHUB_ENV"
    echo "PKG_MGR=dnf" >> "$GITHUB_ENV"
    ;;
  *)
    echo "OS_FAMILY=unknown" >> "$GITHUB_ENV"
    echo "PKG_MGR=unknown" >> "$GITHUB_ENV"
    ;;
esac

echo "Detected OS: $ID $VERSION_ID (family: $OS_FAMILY)"
