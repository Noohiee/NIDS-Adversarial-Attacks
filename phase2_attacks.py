import os
import random
from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


def is_malicious(pkt):
    return pkt.haslayer(TCP) or pkt.haslayer(UDP)


def delay_attack(input_pcap, output_pcap, delay_ms=50):
    packets = rdpcap(input_pcap)
    if len(packets) == 0:
        print("No packets found!")
        return

    delay_seconds = delay_ms / 1000.0

    for pkt in packets:
        if is_malicious(pkt):
            pkt.time = float(pkt.time) + delay_seconds

    wrpcap(output_pcap, packets)
    print("Delay attack complete →", output_pcap)


def reorder_attack(input_pcap, output_pcap, window_size=10, seed=1):
    random.seed(seed)
    packets = rdpcap(input_pcap)
    if len(packets) == 0:
        print("No packets found!")
        return

    new_packets = []
    for i in range(0, len(packets), window_size):
        chunk = list(packets[i:i + window_size])
        random.shuffle(chunk)
        new_packets.extend(chunk)

    wrpcap(output_pcap, new_packets)
    print("Reorder attack complete →", output_pcap)


def padding_attack(input_pcap, output_pcap, pad_bytes=20):
    packets = rdpcap(input_pcap)
    if len(packets) == 0:
        print("No packets found!")
        return

    new_packets = []
    for pkt in packets:
        p = pkt.copy()

        if p.haslayer(Raw):
            try:
                payload = bytes(p[Raw].load)
                p[Raw].load = payload + (b"\x00" * pad_bytes)

                if p.haslayer(IP):
                    del p[IP].len
                    del p[IP].chksum
                if p.haslayer(TCP):
                    del p[TCP].chksum
                if p.haslayer(UDP):
                    del p[UDP].len
                    del p[UDP].chksum
            except Exception:
                pass

        new_packets.append(p)

    wrpcap(output_pcap, new_packets)
    print("Padding attack complete →", output_pcap)


def header_edit_attack(input_pcap, output_pcap, ttl_delta=5, tcp_win_delta=100):
    packets = rdpcap(input_pcap)
    if len(packets) == 0:
        print("No packets found!")
        return

    new_packets = []
    for pkt in packets:
        p = pkt.copy()

        if p.haslayer(IP):
            new_ttl = int(p[IP].ttl) + ttl_delta
            p[IP].ttl = max(1, min(255, new_ttl))
            del p[IP].chksum

        if p.haslayer(TCP):
            new_win = int(p[TCP].window) + tcp_win_delta
            p[TCP].window = max(1, min(65535, new_win))
            del p[TCP].chksum

        new_packets.append(p)

    wrpcap(output_pcap, new_packets)
    print("Header-edit attack complete →", output_pcap)


if __name__ == "__main__":
    os.makedirs("pcaps_out", exist_ok=True)

    # IMPORTANT: this matches your screenshot (double .pcap)
    input_file = "pcaps_in/cic_small.pcap"


    delay_attack(input_file, "pcaps_out/cic_delay.pcap", delay_ms=100)
    reorder_attack(input_file, "pcaps_out/cic_reorder.pcap", window_size=10)
    padding_attack(input_file, "pcaps_out/cic_padding.pcap", pad_bytes=30)
    header_edit_attack(input_file, "pcaps_out/cic_headeredit.pcap", ttl_delta=5, tcp_win_delta=200)
