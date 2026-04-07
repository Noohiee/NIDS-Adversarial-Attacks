from scapy.all import PcapReader, wrpcap

pkts = []
for i, pkt in enumerate(PcapReader("pcaps_in/cic_thursday.pcap.pcap")):
    pkts.append(pkt)
    if i == 5000:   # small sample
        break

wrpcap("pcaps_in/cic_small.pcap", pkts)
print("Small PCAP created")
