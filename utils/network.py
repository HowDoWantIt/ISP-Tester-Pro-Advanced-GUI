import time
import socket

def measure_latency(host, port=53, timeout=2):
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.time() - start) * 1000, 2)  # milliseconds
    except Exception:
        return None

def detect_dns_hijacking(fake_domain="example.invalid", dns_server="8.8.8.8"):
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    try:
        answer = resolver.resolve(fake_domain, lifetime=2)
        return True  # Receiving a response = potential hijacking
    except dns.resolver.NXDOMAIN:
        return False
    except:
        return None  # Error
