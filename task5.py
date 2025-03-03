from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

non_ip_count = 0  # Counter for non-IP packets

def packet_callback(packet):
    global non_ip_count

    if IP in packet:  # Process only IP packets
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        protocol = "Unknown"
        src_port, dst_port = "N/A", "N/A"

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        print(f"IP {ip_src}:{src_port} -> {ip_dst}:{dst_port} | Protocol: {protocol}")

        # Print first 50 bytes of payload (if exists)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            print(f"Payload: {payload[:50]}\n")

    else:
        non_ip_count += 1
        if non_ip_count % 10 == 0:  # Print every 10 non-IP packets
            print(f"⚠️ Non-IP packets detected: {non_ip_count} | Example: {packet.summary()}")

def main():
    print("🚀 Starting packet sniffer... Press Ctrl+C to stop.")
    
    # Sniff only IPv4 packets, ignoring ARP, STP, etc.
    sniff(prn=packet_callback, store=0, filter="ip")

if __name__ == "__main__":
    main()
