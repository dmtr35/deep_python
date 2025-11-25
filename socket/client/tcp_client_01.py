#!/bin/python3

import argparse
import socket
import sys
import textwrap

marker = "[SERVER_DONE]"

class Client:
    def __init__(self, args, buffer):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def sendall(self):
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.sendall(self.buffer)
            self.socket.shutdown(socket.SHUT_WR)
        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response.endswith(marker):
                    print('> ')
                    print(response[:-len(marker)])
                    self.socket.close()
                    sys.exit()
                elif response:
                    print(response)
                    buffer = input('> ')
                    buffer += '\n'
                    self.socket.sendall(buffer.encode())
        except KeyboardInterrupt:
            print('User terminated')
            self.socket.close()
            sys.exit()


def start_tcp_client():
    parser = argparse.ArgumentParser(
        description='client tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            tcp_client -t 192.168.2.100 - p 9999
    '''))
    parser.add_argument('-t', '--target', default='192.168.2.100', help='specified IP')
    parser.add_argument('-p', '--port', type=int, default='9999', help='specified PORT')
    args = parser.parse_args()

    buffer = sys.stdin.read().encode()

    cl = Client(args, buffer)
    cl.sendall()

if __name__ in '__main__':
    start_tcp_client()



