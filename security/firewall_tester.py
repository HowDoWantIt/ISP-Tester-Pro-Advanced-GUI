def test_firewall_and_ports(open_ports, log):
    risky_ports = [21, 23, 445, 139, 3389]  # FTP, Telnet, SMB, NetBIOS, RDP
    dangerous = [p for p in open_ports if p in risky_ports]

    log("🧱 Checking firewall and open ports security...")
    if dangerous:
        log(f"🚨 Dangerous ports are open: {dangerous}")
        log("⚠ It is highly recommended to close these ports or apply filtering rules.")
    else:
        log("✅ No critical ports are open. Your firewall appears to be properly configured.")
