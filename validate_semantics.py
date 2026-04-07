from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from collections import Counter

def check_semantics(pcap_file):
    packets = rdpcap(pcap_file)
    broken = 0
    reasons = []

    for p in packets:
        if p.haslayer(IP):
            if p[IP].ttl <= 0:
                broken += 1
                reasons.append("TTL=0")

        if p.haslayer(TCP):
            if p[TCP].window <= 0:
                broken += 1
                reasons.append("TCP window=0")
            if p[TCP].flags == 0:
                broken += 1
                reasons.append("No TCP flags")

        if p.haslayer(Raw):
            if len(p[Raw].load) == 0:
                broken += 1
                reasons.append("Empty payload")

    print(f"\n{pcap_file}")
    print(f"  Total packets : {len(packets)}")
    print(f"  Broken packets: {broken}/{len(packets)}")
    if reasons:
        print(f"  Breakdown     : {dict(Counter(reasons))}")
    else:
        print(f"  Breakdown     : No semantic issues found")

if __name__ == "__main__":
    files = [
        "pcaps_in/cic_small.pcap",
        "pcaps_out/cic_delay.pcap",
        "pcaps_out/cic_reorder.pcap",
        "pcaps_out/cic_padding.pcap",
        "pcaps_out/cic_headeredit.pcap",
    ]

    for f in files:
        check_semantics(f)