import requests

def test_transparent_proxy(log):
    log("🕵 Checking for transparent proxy...")
    try:
        res = requests.get("http://httpbin.org/headers", timeout=5)
        headers = res.json().get("headers", {})
        if "Via" in headers or "X-Forwarded-For" in headers:
            log(f"⚠ Transparent proxy detected: {headers.get('Via')}, {headers.get('X-Forwarded-For')}")
        else:
            log("✅ No transparent proxy detected.")
    except Exception as e:
        log(f"[!] Error during transparent proxy check: {e}")

def test_proxy_headers(log):
    log("📡 Full proxy headers inspection...")
    try:
        res = requests.get("http://httpbin.org/headers", timeout=5)
        headers = res.json().get("headers", {})
        proxy_headers = ["X-Real-IP", "X-Forwarded-Proto", "Forwarded", "Client-IP"]
        suspicious = [f"{h}: {headers[h]}" for h in proxy_headers if h in headers]
        if suspicious:
            log("⚠ Suspicious proxy-related headers detected:")
            for s in suspicious:
                log(f"   → {s}")
        else:
            log("✅ No suspicious proxy headers found.")
    except Exception as e:
        log(f"⚠ Error while inspecting headers: {e}")
