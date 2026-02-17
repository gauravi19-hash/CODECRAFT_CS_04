from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        proto_name = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(protocol, "Other")

        print("\n=== Packet Captured ===")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {proto_name}")

        # TCP/UDP Ports
        if packet.haslayer(TCP):
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        # Payload Data
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload        : {payload[:50]}")  # limit output

def main():
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    
    sniff(
        prn=process_packet,
        store=False
    )

if __name__ == "__main__":
    main()
