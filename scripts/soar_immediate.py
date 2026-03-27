#!/usr/bin/env python3
"""
Immediate response for event-driven CRITICAL findings.
Fires within seconds of webhook trigger — does not wait for full assessment.
Currently handles: SSH_BRUTE_FORCE (ban IP), MALICIOUS_PROCESS (kill PID).
"""
import os, subprocess, sys

FINDING_TYPE = os.environ.get("EVENT_FINDING_TYPE", "").strip()
SRC_IP       = os.environ.get("EVENT_SRC_IP", "").strip()
PID          = os.environ.get("EVENT_PID", "").strip()

def ban_ip(ip: str):
    """Block IP using nftables (preferred) or iptables fallback."""
    if not ip:
        print("[Immediate] No src_ip provided, skipping IP ban")
        return
    # Try fail2ban first (persists across reboots)
    r = subprocess.run(["fail2ban-client", "set", "sshd", "banip", ip],
                       capture_output=True, text=True)
    if r.returncode == 0:
        print(f"[Immediate] fail2ban banned {ip}")
        return
    # Fallback: nftables immediate drop
    r = subprocess.run(["nft", "add", "rule", "inet", "filter", "input",
                        "ip", "saddr", ip, "drop"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        print(f"[Immediate] nftables dropped {ip}")
    else:
        # Last resort: iptables
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False)
        print(f"[Immediate] iptables dropped {ip}")

def kill_process(pid: str):
    if not pid:
        return
    subprocess.run(["kill", "-9", pid], check=False)
    print(f"[Immediate] Killed PID {pid}")

def main():
    print(f"[Immediate] Responding to {FINDING_TYPE} | ip={SRC_IP} pid={PID}")
    if FINDING_TYPE == "SSH_BRUTE_FORCE":
        ban_ip(SRC_IP)
    elif FINDING_TYPE == "MALICIOUS_PROCESS":
        kill_process(PID)
    elif FINDING_TYPE == "OPEN_PORT":
        # Re-apply Zero Trust firewall immediately
        subprocess.run(["bash", "scripts/zero_trust.sh"], check=False)
    else:
        print(f"[Immediate] No immediate action defined for {FINDING_TYPE}")
        sys.exit(0)

if __name__ == "__main__":
    main()
