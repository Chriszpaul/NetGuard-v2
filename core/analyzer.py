from scapy.layers.inet import IP, TCP, UDP, ICMP

def analyze_packets(packets):
    traffic = {}
    packet_count = {}
    packet_details = []
    protocol_stats = {}

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "OTHER"
            port = None
            flags = ""

            # ============================
            # PROTOCOL & PORT DETECTION
            # ============================
            if TCP in pkt:
                port = pkt[TCP].dport
                flags = str(pkt[TCP].flags) # Capture TCP Flags (S, A, PA, etc.)

                # Mapping common ports to names for the Dashboard
                if port == 80: proto = "HTTP"
                elif port == 443: proto = "HTTPS"
                elif port == 22: proto = "SSH"
                elif port == 23: proto = "TELNET"
                elif port == 21: proto = "FTP"
                elif port == 25: proto = "SMTP"
                elif port == 3389: proto = "RDP"
                elif port == 445: proto = "SMB"
                else: proto = "TCP"

            elif UDP in pkt:
                port = pkt[UDP].dport
                if port == 53: proto = "DNS"
                elif port in [67, 68]: proto = "DHCP"
                elif port == 161: proto = "SNMP"
                else: proto = "UDP"

            elif ICMP in pkt:
                proto = "ICMP"
                port = None

            # ============================
            # STATISTICS & MAPPING
            # ============================
            protocol_stats[proto] = protocol_stats.get(proto, 0) + 1
            
            # Group ports by Source IP for Port Scan Detection
            if src not in traffic:
                traffic[src] = []
            traffic[src].append(port)
            
            packet_count[src] = packet_count.get(src, 0) + 1

            # ============================
            # ENRICHED PACKET DETAILS
            # ============================
            packet_details.append({
                "src_ip": src,
                "dst_ip": dst,
                "protocol": proto,
                "port": port,
                "flags": flags, # New: Added for advanced detection
                "packet_size": len(pkt),
                "packet_count": packet_count[src]
            })

    return traffic, packet_count, packet_details, protocol_stats