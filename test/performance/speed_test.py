import speedtest

def run_speed_test(log):
    log("🔄 Running internet speed test using speedtest.net...")
    try:
        st = speedtest.Speedtest()
        st.get_best_server()

        log("⏳ Measuring download speed...")
        download_speed = st.download() / 1_000_000  # Mbps

        log("⏳ Measuring upload speed...")
        upload_speed = st.upload() / 1_000_000  # Mbps

        ping_result = st.results.ping

        log(f"⬇ Download speed: {download_speed:.2f} Mbps")
        log(f"⬆ Upload speed: {upload_speed:.2f} Mbps")
        log(f"📡 Latency (Ping): {ping_result:.1f} ms")

        return {
            "download": round(download_speed, 2),
            "upload": round(upload_speed, 2),
            "latency": round(ping_result, 1)
        }

    except Exception as e:
        log(f"[!] Error during speed test: {e}")
        return {
            "download": 0,
            "upload": 0,
            "latency": -1
        }
