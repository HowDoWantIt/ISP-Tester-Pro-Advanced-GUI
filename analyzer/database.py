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
import json
import os
import gzip
from datetime import datetime
from geopy.geocoders import Nominatim

# Path to results database file
RESULT_FILE = "results.json"

# Smart result saving with extended metadata
def save_result(data, report, category="general"):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "category": category,
        "ip": get_public_ip(),
        "location": get_geolocation(),
        "data": data,
        "report": report
    }
    with open(RESULT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

# Get public IP address
def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return "Unknown"

# Get user geolocation
def get_geolocation():
    try:
        ip = get_public_ip()
        geo = requests.get(f"https://ipapi.co/{ip}/json").json()
        return f"{geo.get('country_name', '')} - {geo.get('city', '')}"
    except:
        return "Unknown"

# Archive old results
def compress_old_results():
    if os.path.exists(RESULT_FILE):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        gzip_path = f"archive_results_{timestamp}.json.gz"
        with open(RESULT_FILE, 'rb') as f_in:
            with gzip.open(gzip_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(RESULT_FILE)

# Latency alert threshold
def check_latency_alert(latency):
    return latency > 300  # ms

# Function to log IPv6 status and details
def check_ipv6(log):
    result = check_ipv6_support()
    for line in result["logs"]:
        log(line)
    if result["chart_path"]:
        log(f"📊 Latency chart saved to: {result['chart_path']}")
    if result["traceroute"]:
        log("\n🌐 IPv6 Traceroute Path:")
        log(result["traceroute"])
    if result["firewall"]:
        log("\n🔥 IPv6 Firewall Status:")
        log(result["firewall"])

# Run full DNS tests
def run_all_dns_tests(log):
    log("🧪 Running DNS tests...")
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
            alert = " 🚨" if check_latency_alert(elapsed) else ""
            log(f"✅ {name} DNS ({ip}) responded. IP: {answer[0]} ⏱ {elapsed:.1f} ms{alert}")
            times.append((name, elapsed))
            save_result({"server": ip, "latency": elapsed}, f"Response from {name}", category="dns")
        except Exception as e:
            log(f"❌ {name} DNS ({ip}) failed to respond: {e}")
            save_result({"server": ip}, f"No response: {e}", category="dns")

    if times:
        labels, values = zip(*times)
        plt.figure()
        plt.bar(labels, values)
        plt.ylabel("ms")
        plt.title("DNS Response Times")
        plt.xticks(rotation=45)
        plt.tight_layout()
        chart_path = "/mnt/data/dns_response_times.png"
        plt.savefig(chart_path)
        plt.close()
        log(f"📊 DNS response time chart saved to: {chart_path}")

    log("\n🔍 DNS response validity analysis:")
    try:
        response = dns.resolver.resolve("example.com", "A")
        if response:
            log(f"✔ Valid response: {response[0]}")
    except Exception as e:
        log(f"⚠ Error in DNS response analysis: {e}")

    log("\n🔐 Testing DNS over HTTPS (DoH):")
    try:
        doh_url = "https://cloudflare-dns.com/dns-query"
        headers = {"accept": "application/dns-json"}
        r = requests.get(doh_url, params={"name": "example.com", "type": "A"}, headers=headers, timeout=3)
        if r.ok:
            log("✔ DoH response received.")
        else:
            log("❌ Failed to receive DoH response.")
    except Exception as e:
        log(f"⚠ DoH test error: {e}")

    log("\n🧪 Testing DNS Hijacking:")
    try:
        test_domain = "nonexistentdomain123456789.com"
        result = dns.resolver.resolve(test_domain, "A")
        if result:
            log("⚠ Unexpected response for fake domain. Hijacking suspected!")
    except dns.resolver.NXDOMAIN:
        log("✔ No response for fake domain. Normal behavior.")
    except Exception as e:
        log(f"⚠ Hijacking test error: {e}")

    log("\n🗂 DNS Cache Inspection:")
    try:
        if platform.system().lower() == "windows":
            res = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True)
            log(res.stdout[:1000])
        else:
            res = subprocess.run(["systemd-resolve", "--statistics"], capture_output=True, text=True)
            log(res.stdout.strip())
    except Exception as e:
        log(f"⚠ DNS cache check error: {e}")

    log("\n🔍 System DNS configuration:")
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
        log(f"⚠ Error retrieving system DNS config: {e}")
