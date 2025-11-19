from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from datetime import datetime

def analyze_packet(packet):
    print("\n" + "-"*80)
    print(f"📦 Packet captured at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Check if packet has an Ethernet layer
    if Ether in packet:
        ether = packet[Ether]
        print(f"🔹 Ethernet Frame: {ether.src}s → {ether.dst}")
    
    # Check for IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"🌐 IP Packet: {ip_layer.src} → {ip_layer.dst}")
        print(f"   ↳ Protocol: {ip_layer.proto}")
        
        # Identify protocol type
        if ip_layer.proto == 6 and TCP in packet:  # TCP
            tcp = packet[TCP]
            print(f"   🧩 TCP Segment: {tcp.sport} → {tcp.dport}")
            print(f"   Flags: {tcp.flags}")
            if tcp.payload:
                print(f"   Payload: {bytes(tcp.payload)[:50]}...")
                
        elif ip_layer.proto == 17 and UDP in packet:  # UDP
            udp = packet[UDP]
            print(f"   🧩 UDP Datagram: {udp.sport} → {udp.dport}")
            if udp.payload:
                print(f"   Payload: {bytes(udp.payload)[:50]}...")

        elif ip_layer.proto == 1 and ICMP in packet:  # ICMP
            icmp = packet[ICMP]
            print(f"   ⚡ ICMP Type: {icmp.type} Code: {icmp.code}")
        else:
            print("   ⚙️ Other Protocol")
    
    # Show raw data
    if packet.payload:
        print(f"🔍 Raw Packet Data: {bytes(packet.payload)[:60]}...")
    
    print("-"*80)

# Start sniffing packets
print("🕵️ Starting packet capture... (Press Ctrl+C to stop)")
sniff(prn=analyze_packet, store=False, count=10)

