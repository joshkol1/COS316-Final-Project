from scapy.all import Ether, IP, TCP, wrpcap,rdpcap

def create():
    # Create a packet list
    packets = []

    # Create a new packet
    packet = Ether() / IP(dst="1.2.3.4") / TCP(dport=80)

    # Add the packet to the packet list
    packets.append(packet)

    # You can create and add more packets here
    packet = Ether() / IP(dst="5.4.3.2") / TCP(dport=30)

    packets.append(packet)

    # Write the packet list to a .pcap file
    wrpcap("example.pcap", packets)

    print("PCAP file created successfully.")

def read():
    # Load packets from the .pcap file
    packets = rdpcap('example.pcap')

    # Iterate over each packet
    for packet in packets:
        # Check if the packet is an IP packet
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            print(f"IP Source: {ip_src}, IP Destination: {ip_dst}")

            # Check if the packet is a TCP packet
            if TCP in packet:
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                print(f"TCP Source Port: {tcp_sport}, TCP Destination Port: {tcp_dport}")

        print("-----")

if __name__ == "__main__":
    create()
    read()