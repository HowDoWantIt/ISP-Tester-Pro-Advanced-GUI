import socket
import requests
import ssl
import subprocess
import platform
import shutil


def run_security_tests(log, open_ports=[]):
    log("\U0001f512 Starting full security assessment...")
    check_firewall_and_ports(open_ports, log)
    check_dns_integrity(log)
    check_proxy_headers(log)
    check_https_support(log)
    check_vpn_ipsec(log)
    log("\u2705 Security checks completed.")


# ---------------- FIREWALL ----------------
def check_firewall_and_ports(open_ports, log):
    risky_ports = [21, 23, 445, 139, 3389]
    dangerous = [p for p in open_ports if p in risky_ports]
    log("\U0001f6e1 Checking firewall and open ports...")
    if dangerous:
        log(f"\U0001f6a8 Risky open ports detected: {dangerous}")
    else:
        log("\u2705 No risky ports are open.")

    os_name = platform.system().lower()
    if os_name == "windows":
        check_windows_firewall_status(log)
    elif os_name == "linux":
        analyze_linux_firewall_rules(log)
    else:
        log("\u26a0 Unknown OS - skipping firewall test.")


def check_windows_firewall_status(log):
    try:
        result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            log(result.stdout.strip()[:1000])
        else:
            log("\u26a0 Failed to retrieve Windows firewall status.")
    except Exception as e:
        log(f"\u26a0 Error checking Windows firewall: {e}")


def analyze_linux_firewall_rules(log):
    try:
        if shutil.which("ufw"):
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
            log("UFW:")
            log(res.stdout.strip()[:1000])
        elif shutil.which("iptables"):
            res = subprocess.run(["iptables", "-L"], capture_output=True, text=True, timeout=5)
            log("iptables:")
            log(res.stdout.strip()[:1000])
        elif shutil.which("firewall-cmd"):
            res = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=5)
            log("firewalld:")
            log(res.stdout.strip())
        else:
            log("\u26a0 No firewall tool found.")
    except Exception as e:
        log(f"\u26a0 Error analyzing Linux firewall: {e}")


# ---------------- DNS ----------------
def check_dns_integrity(log):
    log("\U0001f9ea Checking DNS integrity...")
    test_domain = "nonexistent.example.dns"
    resolvers = {
        "Google": "8.8.8.8",
        "Cloudflare": "1.1.1.1",
        "OpenDNS": "208.67.222.222"
    }
    for name, ip in resolvers.items():
        try:
            res = subprocess.run(["nslookup", test_domain, ip], capture_output=True, text=True, timeout=3)
            out = res.stdout.strip()
            if "Address:" in out:
                log(f"\u26a0 Potential DNS Hijacking via {name}: {out}")
            else:
                log(f"\u2705 {name} did not resolve fake domain.")
        except Exception as e:
            log(f"\u26a0 DNS test failed for {name}: {e}")

    # DNS Leak Test (Advanced)
    try:
        res = requests.get("https://www.dnsleaktest.com/json/", timeout=5)
        data = res.json()
        servers = data.get("dns_servers", [])
        if servers:
            for s in servers:
                log(f"\U0001f50e DNS responder: {s.get('ip', 'Unknown')} ({s.get('country_name', 'Unknown')})")
        else:
            log("\u26a0 No DNS servers returned.")
    except Exception as e:
        log(f"\u26a0 DNS leak check failed: {e}")


# ---------------- PROXY ----------------
def check_proxy_headers(log):
    log("\U0001f4e1 Checking proxy headers...")
    try:
        res = requests.get("http://httpbin.org/headers", timeout=5)
        headers = res.json().get("headers", {})
        proxy_indicators = ["Via", "X-Forwarded-For", "X-Real-IP", "Forwarded", "Client-IP"]
        for h in proxy_indicators:
            if h in headers:
                log(f"\u26a0 Proxy header detected → {h}: {headers[h]}")
        if not any(h in headers for h in proxy_indicators):
            log("\u2705 No proxy headers found.")
    except Exception as e:
        log(f"\u26a0 Error checking proxy headers: {e}")


# ---------------- HTTPS ----------------
def check_https_support(log):
    log("\U0001f512 Checking HTTPS support...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection(("www.google.com", 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname="www.google.com") as ssock:
                cert = ssock.getpeercert()
                log("\u2705 HTTPS handshake successful.")
                log(f"  Subject: {cert.get('subject', 'N/A')}")
    except Exception as e:
        log(f"\u26a0 HTTPS failed: {e}")


# ---------------- VPN ----------------
def check_vpn_ipsec(log):
    log("\U0001f310 Checking VPN/IPSec...")
    try:
        output = subprocess.getoutput("ipconfig" if platform.system().lower() == "windows" else "ifconfig")
        if any(k in output.lower() for k in ["tun", "ppp", "vpn"]):
            log("\u2705 VPN or tunnel interface detected.")
        else:
            log("\u2139 No active VPN/IPSec interface found.")
    except Exception as e:
        log(f"\u26a0 VPN check failed: {e}")
