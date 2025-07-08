import socket
import subprocess
import requests

def test_dns_hijacking(log):
    log("🤪 Testing DNS Hijacking...")
    try:
        fake_domain = "fake.testdomain"
        ip = socket.gethostbyname(fake_domain)
        log(f"⚠ Unexpected response for fake domain: {ip}")
    except socket.gaierror:
        log("✅ DNS Hijacking does not seem to be active.")

def test_dns_hijacking_advanced(log):
    log("🧠 Advanced DNS Hijacking Test using multiple DNS resolvers...")
    try:
        test_domain = "test.nonexistentdomain1234.com"
        resolvers = {
            "Google": "8.8.8.8",
            "Cloudflare": "1.1.1.1",
            "OpenDNS": "208.67.222.222"
        }
        for name, dns_ip in resolvers.items():
            result = subprocess.run([
                "nslookup", test_domain, dns_ip
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
            output = result.stdout.strip()
            if "Name:" in output and "Address:" in output:
                log(f"⚠ Possible Hijacking from {name} DNS:\n{output}")
            else:
                log(f"✅ {name} DNS did not return a result — good sign.")
    except Exception as e:
        log(f"⚠ General error during advanced Hijacking test: {e}")

def test_dns_leak(log):
    log("🔍 Testing DNS Leak...")
    try:
        res = requests.get("https://cloudflare-dns.com/dns-query", timeout=3)
        if res.status_code == 200:
            log("✅ Valid DNS response received from Cloudflare DoH.")
        else:
            log("⚠ Possible DNS Leak detected.")
    except Exception:
        log("⚠ Unable to test for DNS Leak — request failed.")

def test_dns_leak_advanced(log):
    log("🔬 Advanced DNS Leak Test via dnsleaktest.com...")
    try:
        res = requests.get("https://www.dnsleaktest.com/json/", timeout=5)
        if res.status_code == 200:
            data = res.json()
            servers = data.get("dns_servers", [])
            if servers:
                for server in servers:
                    ip = server.get("ip", "Unknown")
                    country = server.get("country_name", "N/A")
                    log(f"🔎 DNS Responder: {ip} ({country})")
            else:
                log("⚠ No DNS servers were detected.")
        else:
            log("⚠ Unable to fetch leak test data.")
    except Exception as e:
        log(f"⚠ Error during DNS Leak check: {e}")
