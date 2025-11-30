#!/usr/bin/env python3

from scapy.all import sniff, TCP, IP

def packet_callback(packet):
    print('here')

    if packet[TCP].payload:
        mypacket = str(packet[TCP].payload)
        if 'user' in mypacket.lower() or 'pass' in mypacket.lower():
            print(f"[*] Destination: {packet[IP].dst}")
            print(f"[*] {str(packet[TCP].payload)}")


def main():
    # store=0 - не будет хранить пакеты в памяти
    sniff(filter='tcp port 110 or tcp port 25 or tcp port 143',
           prn=packet_callback, store=0)

if __name__ in "__main__":
    main()

