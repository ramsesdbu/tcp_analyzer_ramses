from scapy.all import rdpcap, TCP, IP
import pandas as pd

def parse_pcap(file_path):
    """
    Parse file PCAP menggunakan Scapy (tanpa asyncio)
    """
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        raise RuntimeError(f"Gagal membaca file PCAP: {e}")

    rows = []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            rows.append({
                "time": pkt.time,
                "source": pkt[IP].src,
                "destination": pkt[IP].dst,
                "protocol": "TCP",
                "length": len(pkt),
                "sport": pkt[TCP].sport,
                "dport": pkt[TCP].dport,
                "flags": str(pkt[TCP].flags)
            })

    if not rows:
        raise RuntimeError("Tidak ada paket TCP ditemukan dalam file ini")

    return pd.DataFrame(rows)

