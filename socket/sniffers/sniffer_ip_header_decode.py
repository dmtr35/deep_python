import ipaddress
import os
import socket
import struct
import sys

class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        # 0   XXXX|XXXX|XXXXXXXX|XXXXXXXXXXXXXXXX
        # 32  XXXXXXXX XXXXXXXX|XXX|XXXXXXXXXXXXX
        # 64  XXXXXXXX|XXXXXXXX|XXXXXXXX XXXXXXXX
        # 96  XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX
        # 128 XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX
        # 160 XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX

        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # IP-адреса, понятные человеку
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # сопоставляем константы протоколов с их названиями
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print(f'{e} No protocol for {self.protocol_num}')
            self.protocol = str(self.protocol_num)

# (b'E\x88\x00T7l\x00\x008\x01\x85\xa7\x01\x01\x01\x01\xc0\xa8\x02d \x00\x00q\xbb\x00\x03\x00\x01\x81F\x0fi \x00\x00\x00\x00;\xbe\x03\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567', ('1.1.1.1', 0))
class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)

        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def sniff(host):
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    try:
        while True:
            # читаем пакет
            raw_buffer = sniffer.recvfrom(65535)[0]
            # создаем IP-заголовок из первых 20 байт
            ip_header = IP(raw_buffer[0:20])
            # выводим обнаруженные протокол и адреса
            #print(f'Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}')
            if ip_header.protocol == "ICMP":
                print(f'Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}')
                # print(f'Version: {ip_header.ver}')
                # print(f'Header Length: {ip_header.ihl} TTL: {ip_header.ttl}')

                # определяем, где нечинается ICMP-пакет
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + 8]
                # создаем структуру ICMP
                icmp_header = ICMP(buf)
                print(f'ICMP -> Type: {icmp_header.type} Code: {icmp_header.code}\n')
    except KeyboardInterrupt:
        # если мы в Windows, выключаем неизбирательный режим
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()

if __name__ == "__main__":
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.2.100'
    sniff(host)