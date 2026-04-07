from scapy.all import rdpcap, TCP, Raw

def validate_pcap(file):
    packets = rdpcap(file)

    syn = 0
    syn_ack = 0
    ack = 0
    fin = 0
    rst = 0
    http_requests = 0
    http_responses = 0
    malformed = 0

    for pkt in packets:
        if TCP in pkt:
            flags = pkt[TCP].flags

            if flags == 0x02:    # SYN
                syn += 1
            elif flags == 0x12:  # SYN-ACK
                syn_ack += 1
            elif flags == 0x10:  # ACK
                ack += 1
            elif flags & 0x01:   # FIN
                fin += 1
            elif flags & 0x04:   # RST
                rst += 1

            # Check for malformed TCP (no flags at all)
            if flags == 0:
                malformed += 1

        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if b"GET" in payload or b"POST" in payload or b"HTTP/1" in payload[:10]:
                http_requests += 1
            if b"HTTP/1.1 " in payload or b"HTTP/1.0 " in payload:
                http_responses += 1

    # Check handshake validity
    handshake_ok = syn > 0 and syn_ack > 0 and ack > 0
    handshake_balanced = abs(syn - syn_ack) <= max(1, syn * 0.2)  # within 20%

    print(f"\nFile: {file}")
    print(f"  Total packets     : {len(packets)}")
    print(f"  SYN={syn}, SYN-ACK={syn_ack}, ACK={ack}, FIN={fin}, RST={rst}")
    print(f"  Handshake valid   : {'YES' if handshake_ok else 'NO'}")
    print(f"  Handshake balanced: {'YES' if handshake_balanced else 'NO - reorder may have disrupted flow'}")
    print(f"  HTTP requests     : {http_requests}")
    print(f"  HTTP responses    : {http_responses}")
    print(f"  Malformed TCP     : {malformed}")

def compare_to_original(original, modified_files):
    print("\n========== FUNCTIONALITY PRESERVATION SUMMARY ==========")
    orig = get_stats(original)
    for f in modified_files:
        mod = get_stats(f)
        syn_preserved = abs(orig['syn'] - mod['syn']) <= max(1, orig['syn'] * 0.1)
        http_preserved = abs(orig['http'] - mod['http']) <= max(1, orig['http'] * 0.1)
        print(f"\n{f}")
        print(f"  SYN preserved : {'YES' if syn_preserved else 'NO'}")
        print(f"  HTTP preserved: {'YES' if http_preserved else 'NO'}")
        print(f"  Attack functionality likely {'PRESERVED' if syn_preserved and http_preserved else 'DISRUPTED'}")

def get_stats(file):
    packets = rdpcap(file)
    syn = 0
    http = 0
    for pkt in packets:
        if TCP in pkt:
            if pkt[TCP].flags == 0x02:
                syn += 1
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if b"GET" in payload or b"POST" in payload:
                http += 1
    return {'syn': syn, 'http': http}

if __name__ == "__main__":
    files = [
        "pcaps_in/cic_small.pcap",
        "pcaps_out/cic_delay.pcap",
        "pcaps_out/cic_reorder.pcap",
        "pcaps_out/cic_padding.pcap",
        "pcaps_out/cic_headeredit.pcap"
    ]

    for f in files:
        validate_pcap(f)

    compare_to_original(
        "pcaps_in/cic_small.pcap",
        [
            "pcaps_out/cic_delay.pcap",
            "pcaps_out/cic_reorder.pcap",
            "pcaps_out/cic_padding.pcap",
            "pcaps_out/cic_headeredit.pcap"
        ]
    )