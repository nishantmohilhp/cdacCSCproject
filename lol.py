from scapy.all import sniff

def packet_callback(packet): 
    mypacket = str(packet[TCP].payload)
    if 'user' in mypacket.lower() or 'pass' in mypacket.lower():
        print(f"[*] Destination: {packet[IP].dst}")
        print(f"[*] {str(packet[TCP].payload)}")

def main():
    sniff(prn=packet_callback, count=1)

if __name__ == '__main__':
    main()
