from scapy.all import sniff

print("Sniff ARP...")
# pkts = sniff(count=3, filter="ip host 192.168.2.21", iface="enp7s0")
pkts = sniff(count=3, filter="ip host 192.168.2.21", iface="br0")
print("Done:", pkts)
