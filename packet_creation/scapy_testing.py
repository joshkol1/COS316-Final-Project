from scapy.all import Ether, IP, TCP, wrpcap,rdpcap

def create():
    # Create a packet list
    packets = []

    # Create a new packet
    packet = Ether() / IP(dst="1.2.3.4",src="4.3.6.8") / TCP(dport=80)

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
        print(packet.show())
        print("-----")

if __name__ == "__main__":
    create()
    read()