def analyze_results(results):
    report = []
    report.append("📊 Results Analysis:")

    # Speed Analysis
    if "speed" in results:
        download = results["speed"].get("download", 0)
        upload = results["speed"].get("upload", 0)
        latency = results["speed"].get("latency", 0)

        if download < 10:
            report.append("🚨 Download speed is critically low.")
        elif download < 25:
            report.append("⚠ Download speed is moderate.")
        else:
            report.append("✅ Download speed is good.")

        if upload < 2:
            report.append("🚨 Upload speed is very low.")

        if latency > 300:
            report.append(f"⚠ High latency detected ({latency} ms).")
        else:
            report.append(f"⏱ Latency is within acceptable range ({latency} ms).")

    # IPv6 Analysis
    if "ipv6" in results:
        ipv6 = results["ipv6"]
        if not ipv6.get("supported"):
            report.append("⚠ IPv6 is not supported.")
        else:
            if ipv6.get("public_address"):
                report.append("✅ Public IPv6 address detected.")
            if ipv6.get("link_local"):
                report.append("ℹ Link-Local address present.")
            if ipv6.get("temporary_disabled"):
                report.append("🔒 Temporary IPv6 (Privacy Extension) is disabled.")
            if ipv6.get("slaac_active"):
                report.append("📡 SLAAC is active.")
            if ipv6.get("router_advertisement"):
                report.append("⚠ Warning: Suspicious Router Advertisement (RA) detected.")
            if ipv6.get("ipsec_enabled"):
                report.append("🔐 IPsec is enabled.")

    # DNS Analysis
    if "dns" in results:
        best_dns = results["dns"].get("best")
        hijack = results["dns"].get("hijacking", False)
        if best_dns:
            report.append(f"🏆 Best DNS: {best_dns['name']} ({best_dns['ip']}) with {best_dns['latency']} ms")
        if hijack:
            report.append("🚨 DNS Hijacking is suspected!")
        if results["dns"].get("doh_enabled"):
            report.append("🔒 DNS over HTTPS (DoH) is enabled.")

    # DNS Cache Analysis
    if "dns_cache" in results:
        ttl = results["dns_cache"].get("ttl")
        if ttl:
            report.append(f"🧠 DNS cache is active. Average TTL: {ttl} seconds")

    # Location Summary
    if "location" in results:
        loc = results["location"]
        report.append(f"🌍 Location: {loc}")

    report.append("📌 End of analysis.")
    return "\n".join(report)
