import platform
import subprocess
import shutil
import socket

def test_firewall_and_ports_full(open_ports, log):
    log("🧱 Firewall and open ports security analysis...")

    # 1. High-risk ports
    risky_ports = [21, 23, 445, 139, 3389]
    dangerous = [p for p in open_ports if p in risky_ports]
    if dangerous:
        log(f"🚨 High-risk open ports detected: {dangerous}")
    else:
        log("✅ No dangerous ports are open.")

    # 2. Firewall check based on OS
    os_name = platform.system().lower()
    if os_name == "windows":
        check_windows_firewall_status(log)
    elif os_name == "linux":
        analyze_linux_firewall_rules(log)
    else:
        log("⚠ Unknown operating system. Firewall test skipped.")

    # 3. Attempt to identify services on open ports
    for port in open_ports:
        try:
            banner = simulate_syn_probe(port)
            if banner:
                log(f"🔍 Port {port} → Service response: {banner}")
            else:
                log(f"⚠ Port {port} is open but no identifiable service was detected.")
        except Exception:
            log(f"⚠ Error analyzing port {port}")

    log("📌 Completed firewall and port security analysis.")

# ---------------------------
def simulate_syn_probe(port, host="127.0.0.1", timeout=1.5):
    """Basic TCP probe to detect banner or initial response"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024)
            return response.decode(errors='ignore').strip()
    except:
        return None

def check_windows_firewall_status(log):
    try:
        log("🛡 Checking Windows Firewall status...")
        result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            output = result.stdout.strip()
            log(output[:1000] + ("\n..." if len(output) > 1000 else ""))
        else:
            log("⚠ Failed to execute netsh command.")
    except Exception as e:
        log(f"⚠ Error checking Windows Firewall: {e}")

def analyze_linux_firewall_rules(log):
    log("🛡 Checking Linux firewall configuration...")
    try:
        if shutil.which("ufw"):
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
            log("🔍 UFW Status:")
            output = res.stdout.strip()
            log(output[:1000] + ("\n..." if len(output) > 1000 else ""))
        elif shutil.which("iptables"):
            res = subprocess.run(["iptables", "-L"], capture_output=True, text=True, timeout=5)
            log("🔍 iptables Rules:")
            output = res.stdout.strip()
            log(output[:1000] + ("\n..." if len(output) > 1000 else ""))
        elif shutil.which("firewall-cmd"):
            res = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=5)
            log("🔍 firewalld Status:")
            log(res.stdout.strip())
        else:
            log("⚠ No firewall tool found on the system.")
    except Exception as e:
        log(f"⚠ Error analyzing Linux firewall: {e}")
