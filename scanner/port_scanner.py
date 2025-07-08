import socket
import time

def run_port_scan(log, target_host="127.0.0.1", timeout=0.5):
    log(f"🔍 Starting TCP port scan on {target_host}...")

    open_ports = []
    closed_ports = []
    timeout_ports = []
    banner_results = []
    port_range = range(0, 1024)  # Can be extended to 65535

    for port in port_range:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            start_time = time.time()
            result = sock.connect_ex((target_host, port))
            response_time = (time.time() - start_time) * 1000  # milliseconds

            if result == 0:
                log(f"[OPEN] Port {port} is open (⏱ {response_time:.2f} ms)")
                banner = grab_banner(sock)
                open_ports.append((port, response_time, banner))
                if banner:
                    banner_results.append((port, banner.strip()))
            elif result == 111 or result == 10061:
                closed_ports.append(port)
            else:
                timeout_ports.append(port)

    # 📊 Result Summary
    log("\n📊 Scan Summary:")
    log(f" - Total ports scanned: {len(port_range)}")
    log(f" - Open ports: {len(open_ports)}")
    log(f" - Closed ports: {len(closed_ports)}")
    log(f" - No response (timeout): {len(timeout_ports)}")

    # 🔓 Open Port Details
    if open_ports:
        log("\n🔓 List of Open Ports:")
        for port, resp_time, banner in open_ports:
            log(f"  → Port {port} | Response in {resp_time:.2f} ms")
            if banner:
                log(f"     ⚡ Detected Service: {banner.strip()}")
            else:
                log("     ⚠️ Unknown service (no banner received)")
    else:
        log("✅ No open ports found.")

    # 📋 Detected Service Banners
    if banner_results:
        log("\n🧩 Identified Services via Banner:")
        for port, banner in banner_results:
            log(f" - Port {port}: {banner}")
    else:
        log("\nℹ️ No service banners were captured.")

def grab_banner(sock):
    try:
        sock.settimeout(0.7)
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024)
        return banner.decode(errors='ignore')
    except:
        return None
