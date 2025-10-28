import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import rdpcap, TCP, IP
import tempfile

st.set_page_config(page_title="TCP Packet Analyzer", layout="wide")
st.title("TCP Packet Analyzer")
st.markdown("Upload a `.pcap` file to analyze TCP packets and detect potential network issues.")

uploaded_file = st.file_uploader("Select a PCAP file", type=["pcap"])

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    rows = []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = pkt[TCP].flags
            rows.append({
                "Source IP": pkt[IP].src,
                "Destination IP": pkt[IP].dst,
                "Flags": str(flags),
                "Source Port": pkt[TCP].sport,
                "Destination Port": pkt[TCP].dport,
                "Length": len(pkt)
            })
    return pd.DataFrame(rows)

def analyze_tcp(df):
    syn_df = df[df["Flags"].str.contains("S", regex=False)]
    rst_df = df[df["Flags"].str.contains("R", regex=False)]
    fin_df = df[df["Flags"].str.contains("F", regex=False)]
    ack_df = df[df["Flags"].str.contains("A", regex=False)]

    syn = len(syn_df)
    rst = len(rst_df)
    fin = len(fin_df)
    ack = len(ack_df)
    total = len(df)

    analysis = []
    if rst > syn * 0.3:
        analysis.append("⚠️ Many reset connections (RST) — possible network instability or connection failures.")
    if fin > syn * 0.5:
        analysis.append("ℹ️ Many closed connections (FIN) — frequent disconnections or timeouts detected.")
    if ack == 0:
        analysis.append("❌ No ACK packets detected — the connection may not be functioning correctly.")
    if not analysis:
        analysis.append("✅ No major issues detected — TCP connections appear normal.")

    # Find problematic IPs (based on RST or FIN)
    problem_ips = pd.concat([rst_df, fin_df])[["Source IP", "Destination IP"]]
    problem_counts = problem_ips.value_counts().reset_index(name="Count")

    return {
        "total": total,
        "syn": syn,
        "rst": rst,
        "fin": fin,
        "ack": ack,
        "notes": analysis,
        "problem_ips": problem_counts
    }

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getbuffer())
        tmp_path = tmp.name

    st.info("Analyzing packets... please wait a few seconds.")
    df = parse_pcap(tmp_path)

    if len(df) == 0:
        st.warning("No TCP packets detected in this PCAP file.")
        st.stop()

    summary = analyze_tcp(df)

    st.subheader("General Statistics")
    st.write(f"Total TCP Packets: {summary['total']}")
    st.write(f"SYN: {summary['syn']}, ACK: {summary['ack']}, FIN: {summary['fin']}, RST: {summary['rst']}")

    st.subheader("Automatic Analysis")
    for note in summary["notes"]:
        st.write(note)

    # Show problematic IPs
    if not summary["problem_ips"].empty:
        st.subheader("Source/Destination IPs Involved in Problematic Connections")
        st.dataframe(summary["problem_ips"], use_container_width=True)

    # IP Distribution Chart
    st.subheader("Source IP Distribution")
    fig_ip = px.histogram(df, x="Source IP", title="Number of Packets per Source IP")
    st.plotly_chart(fig_ip, use_container_width=True)

    # TCP Flags Chart
    st.subheader("TCP Flags Distribution")
    fig_flags = px.histogram(df, x="Flags", title="TCP Flag Distribution")
    st.plotly_chart(fig_flags, use_container_width=True)
else:
    st.info("Please upload a `.pcap` file to start the analysis.")

