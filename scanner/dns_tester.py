import subprocess
import socket
import time
import matplotlib.pyplot as plt
import platform
import shutil
from statistics import mean
import re
import dns.resolver
import dns.message
import dns.query
import dns.dnssec
import dns.name
import requests


def check_ipv6(log):
    result = check_ipv6_support()
    for line in result["logs"]:
        log(line)

    if result["chart_path"]:
        log(f"📊 Latency chart saved: {result['chart_path']}")

    if result["traceroute"]:
        log("\n🌐 IPv6 Traffic Route:")
        log(result["traceroute"])

    if result["firewall"]:
        log("\n🔥 Initial IPv6 Firewall Status:")
        log(result["firewall"])

def run_all_dns_tests(log):
    log("🧪 Running DNS Tests...")
    dns_servers = [
        ("1.1.1.1", "Cloudflare"),
        ("8.8.8.8", "Google"),
        ("9.9.9.9", "Quad9"),
        ("208.67.222.222", "OpenDNS"),
        ("76.76.2.0", "Control D"),
        ("94.140.14.14", "AdGuard"),
        ("2606:4700:4700::1111", "Cloudflare IPv6"),
        ("2001:4860:4860::8888", "Google IPv6"),
        ("2620:fe::fe", "Quad9 IPv6")
    ]

    times = []
    for ip, name in dns_servers:
        try:
            start = time.time()
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ip]
            answer = resolver.resolve("example.com", "A")
            elapsed = (time.time() - start) * 1000
            log(f"✅ DNS {name} ({ip}) responded. IP: {answer[0]} ⏱ {elapsed:.1f} ms")
            times.append((name, elapsed))
        except Exception as e:
            log(f"❌ DNS {name} ({ip}) failed to respond: {e}")

    if times:
        labels, values = zip(*times)
        plt.figure()
        plt.bar(labels, values)
        plt.ylabel("ms")
        plt.title("DNS Response Times")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("/mnt/data/dns_response_times.png")
        plt.close()
        log("📊 DNS response time chart saved: /mnt/data/dns_response_times.png")

    log("\n🔍 DNS Response Validation:")
    try:
        response = dns.resolver.resolve("example.com", "A")
        if response:
            log(f"✔ Valid response received: {response[0]}")
    except Exception as e:
        log(f"⚠ Error during DNS response validation: {e}")

    log("\n🔐 Checking DNS over HTTPS (DoH):")
    try:
        doh_url = "https://cloudflare-dns.com/dns-query"
        headers = {"accept": "application/dns-json"}
        r = requests.get(doh_url, params={"name": "example.com", "type": "A"}, headers=headers, timeout=3)
        if r.ok:
            log("✔ DoH response received.")
        else:
            log("❌ Failed to receive DoH response.")
    except Exception as e:
        log(f"⚠ DoH check error: {e}")

    log("\n🧪 Checking for DNS Hijacking:")
    try:
        test_domain = "nonexistentdomain123456789.com"
        result = dns.resolver.resolve(test_domain, "A")
        if result:
            log("⚠ Unexpected response for fake domain; possible DNS Hijacking detected!")
    except dns.resolver.NXDOMAIN:
        log("✔ No response for fake domain; behavior is normal.")
    except Exception as e:
        log(f"⚠ Error during Hijacking test: {e}")

    log("\n🗂 Checking DNS Cache Configuration:")
    try:
        if platform.system().lower() == "windows":
            res = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True)
            log(res.stdout[:1000])
        else:
            res = subprocess.run(["systemd-resolve", "--statistics"], capture_output=True, text=True)
            log(res.stdout.strip())
    except Exception as e:
        log(f"⚠ Error checking DNS cache: {e}")

    log("\n🔍 Checking System DNS Settings:")
    try:
        if platform.system().lower() == "windows":
            res = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
            dns_lines = [line.strip() for line in res.stdout.splitlines() if "DNS Servers" in line]
            for line in dns_lines:
                log(f"→ {line}")
        else:
            res = subprocess.run(["cat", "/etc/resolv.conf"], capture_output=True, text=True)
            log(res.stdout.strip())
    except Exception as e:
        log(f"⚠ Error fetching DNS settings: {e}")
