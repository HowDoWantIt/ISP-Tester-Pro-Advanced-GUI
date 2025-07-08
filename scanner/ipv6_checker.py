import subprocess
import socket
import time
import matplotlib.pyplot as plt
import platform
import shutil
from statistics import mean
import re


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


def check_ipv6_support():
    logs = []
    chart_path = None
    traceroute_output = ""
    firewall_status = ""
    latency_results = []

    logs.append("🔍 Checking IPv6 support...")

    test_hosts = [
        ("ipv6.google.com", "[2607:f8b0:4005:805::200e]"),
        ("one.one.one.one", "[2606:4700:4700::1111]")
    ]
    supported = False

    for hostname, fallback_ip in test_hosts:
        try:
            addrinfo = socket.getaddrinfo(hostname, 80, socket.AF_INET6)
            address = addrinfo[0][4][0] if addrinfo else fallback_ip.strip("[]")
        except:
            address = fallback_ip.strip("[]")

        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((address, 80))
            sock.close()
            logs.insert(1, "🟢 IPv6 Connectivity: Active ✅")
            logs.append(f"✔ Successful connection to {hostname} via IPv6 ({address})")
            supported = True
            break
        except Exception as e:
            logs.append(f"✖ Failed to connect to {hostname} via IPv6: {e}")

    if not supported:
        logs.insert(1, "🔴 IPv6 Connectivity: Inactive ❌")
        logs.append("❌ IPv6 is not supported.")
        return {"logs": logs, "chart_path": None, "traceroute": "", "firewall": ""}

    logs.append("\n📥 Local IPv6 Addresses:")
    try:
        for res in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
            logs.append(f"→ {res[4][0]}")
    except:
        logs.append("⚠ Failed to retrieve local IPv6 addresses.")

    logs.append("\n🔎 Checking DNS Leak over IPv6:")
    try:
        res = subprocess.run(["nslookup", "ipv6.google.com"], capture_output=True, text=True)
        if "Address" in res.stdout:
            logs.append("✔ DNS query completed successfully.")
        else:
            logs.append("⚠ DNS response issue detected.")
    except Exception as e:
        logs.append(f"⚠ nslookup error: {e}")

    logs.append("\n📊 Detecting Static vs Dynamic Addresses:")
    try:
        res = subprocess.run(["ip", "-6", "addr"], capture_output=True, text=True)
        lines = res.stdout.splitlines()
        for line in lines:
            if "scope global dynamic" in line:
                logs.append(f"→ {line.strip()} (Dynamic)")
            elif "scope global" in line:
                logs.append(f"→ {line.strip()} (Static)")
    except:
        logs.append("⚠ Unable to detect address types.")

    logs.append("\n📡 Sending ICMPv6 Pings:")
    try:
        cmd = ["ping", "-6", "-c", "2", "ipv6.google.com"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        logs.append(res.stdout.strip())
    except Exception as e:
        logs.append(f"⚠ ICMPv6 error: {e}")

    logs.append("\n🚧 NAT64 Detection:")
    try:
        test_domain = "ipv4only.arpa"
        res = subprocess.run(["dig", test_domain, "AAAA"], capture_output=True, text=True)
        if "AAAA" in res.stdout:
            logs.append(f"✔ AAAA record for {test_domain} found; NAT64 is active.")
        else:
            logs.append("⚠ No AAAA record; NAT64 might be inactive or unavailable.")
    except Exception as e:
        logs.append(f"⚠ NAT64 detection error: {e}")

    logs.append("\n📶 IPv6 Connection Quality (Ping Test)...")
    try:
        is_windows = platform.system().lower() == "windows"
        for i in range(5):
            cmd = ["ping", "-n", "1", "ipv6.google.com"] if is_windows else ["ping", "-6", "-c", "1", "ipv6.google.com"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            output = res.stdout
            if "time=" in output or "زمان=" in output:
                match = re.search(r"time[=<]\s*(\d+(\.\d+)?)", output)
                if match:
                    time_ms = float(match.group(1))
                    latency_results.append(time_ms)
                    logs.append(f"✅ Reply received: {time_ms:.2f} ms")
            else:
                logs.append("❌ No reply received.")
        if latency_results:
            avg_latency = mean(latency_results)
            logs.append(f"📊 Average Latency: {avg_latency:.2f} ms")
            plt.figure()
            plt.plot(latency_results, marker='o', label="Latency (ms)")
            plt.title("IPv6 Latency")
            plt.xlabel("Attempt")
            plt.ylabel("ms")
            plt.legend()
            chart_path = "/mnt/data/ipv6_latency_chart.png"
            plt.savefig(chart_path)
            plt.close()
    except Exception as e:
        logs.append(f"⚠ Ping error: {e}")

    logs.append("\n🔉 Running IPv6 Traceroute:")
    if shutil.which("traceroute"):
        try:
            res = subprocess.run(["traceroute", "-6", "ipv6.google.com"], capture_output=True, text=True, timeout=10)
            traceroute_output = res.stdout.strip()
        except Exception as e:
            traceroute_output = f"⚠ Traceroute error: {e}"
    else:
        traceroute_output = "⚠ 'traceroute' is not installed on this system."

    logs.append("\n🛡 IPv6 Firewall Status:")
    if shutil.which("ip6tables"):
        try:
            res = subprocess.run(["ip6tables", "-L"], capture_output=True, text=True, timeout=5)
            firewall_status = res.stdout.strip()
        except Exception as e:
            firewall_status = f"⚠ ip6tables error: {e}"
    else:
        firewall_status = "⚠ ip6tables is not available on this system."

    logs.append("\n🔐 IPv6 Security Check:")
    try:
        res = subprocess.run(["ip", "-6", "addr", "show"], capture_output=True, text=True)
        public_count = len(re.findall(r'inet6 ([0-9a-f:]+)/(?:\d+)\s+scope global', res.stdout))
        link_local_count = len(re.findall(r'inet6 ([0-9a-f:]+)/(?:\d+)\s+scope link', res.stdout))
        logs.append(f"🌐 Number of public addresses: {public_count}")
        logs.append(f"🔗 Number of link-local addresses: {link_local_count}")

        if "temporary" in res.stdout:
            logs.append("⚠ Temporary address (privacy extension) is enabled.")
        else:
            logs.append("✅ Temporary address is disabled.")

        if "autoconf" in res.stdout:
            logs.append("⚠ SLAAC (Stateless Address Autoconfiguration) is enabled.")
        else:
            logs.append("✅ SLAAC is disabled.")
    except Exception as e:
        logs.append(f"⚠ Address inspection error: {e}")

    if shutil.which("radvdump"):
        try:
            logs.append("🔎 Checking RA via radvdump...")
            res = subprocess.run(["radvdump", "-n", "-p"], capture_output=True, text=True, timeout=5)
            if res.stdout.strip():
                logs.append("⚠ Router Advertisements (RA) detected. Security review recommended.")
            else:
                logs.append("✅ No suspicious RA found.")
        except Exception as e:
            logs.append(f"⚠ radvdump error: {e}")
    else:
        logs.append("⚠ radvdump is not installed.")

    logs.append("🧪 Scanning open ports on IPv6 localhost (::1):")
    open_ports = []
    for port in [22, 80, 443, 8080, 8443]:
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex(("::1", port)) == 0:
                    open_ports.append(port)
        except:
            continue
    if open_ports:
        logs.append(f"⚠ Open ports detected on ::1: {open_ports}")
    else:
        logs.append("✅ No suspicious ports found on ::1.")

    logs.append("🔐 Checking IPsec Configuration:")
    if shutil.which("ipsec"):
        try:
            res = subprocess.run(["ipsec", "status"], capture_output=True, text=True)
            if "INSTALLED" in res.stdout or "ESTABLISHED" in res.stdout:
                logs.append("✔ IPsec connection is active.")
            else:
                logs.append("ℹ IPsec is installed but no active connection found.")
        except Exception as e:
            logs.append(f"⚠ IPsec status error: {e}")
    else:
        logs.append("ℹ IPsec tool is not installed.")

    return {
        "logs": logs,
        "chart_path": chart_path,
        "traceroute": traceroute_output,
        "firewall": firewall_status
    }
