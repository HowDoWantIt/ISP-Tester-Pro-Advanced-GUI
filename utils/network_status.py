import socket
import subprocess
import platform

def check_internet():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return "Connected"
    except:
        return "Disconnected"

def check_ipv6():
    try:
        result = socket.getaddrinfo("ipv6.google.com", None, socket.AF_INET6)
        return len(result) > 0
    except:
        return False

def detect_dns_hijack():
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        answer = resolver.resolve("example.com")
        for r in answer:
            if "93.184.216.34" not in r.to_text():
                return True  # Potential DNS hijack detected
        return False
    except:
        return False

def get_status_summary():
    return {
        "internet": check_internet(),
        "ipv6": check_ipv6(),
        "dns_hijack": detect_dns_hijack()
    }
