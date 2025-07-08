import subprocess
import socket

def detect_vpn_ipsec(log):
    log("🌐 Checking VPN/IPSec connection...")
    try:
        output = subprocess.getoutput("ipconfig" if socket.gethostname().find('.') == -1 else "ifconfig")
        if "tun" in output or "ppp" in output or "vpn" in output.lower():
            log("✅ VPN connection detected.")
        else:
            log("ℹ️ No active VPN or IPSec connection.")
    except Exception as e:
        log(f"[!] Error while checking VPN: {e}")
