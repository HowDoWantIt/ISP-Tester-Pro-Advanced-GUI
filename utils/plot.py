import matplotlib.pyplot as plt

def plot_dns_latency(dns_results, save_path=None):
    names = [r["name"] for r in dns_results if r["latency"] is not None]
    latencies = [r["latency"] for r in dns_results if r["latency"] is not None]

    plt.figure(figsize=(10, 5))
    plt.barh(names, latencies, color="skyblue")
    plt.xlabel("Latency (ms)")
    plt.title("DNS Server Latency Comparison")
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path)
    else:
        plt.show()
