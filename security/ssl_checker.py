import socket
import ssl

def test_https_support(log):
    log("🔐 Testing HTTPS support...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection(("www.google.com", 443)) as sock:
            with context.wrap_socket(sock, server_hostname="www.google.com") as ssock:
                cert = ssock.getpeercert()
                log("✅ HTTPS connection established successfully.")
    except Exception:
        log("⚠ Failed to establish a secure HTTPS connection.")
