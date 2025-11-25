#!/bin/python3

import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

marker = "[SERVER_DONE]"
BHP = b"BHP #> "

def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    try:
        proc = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        return proc.stdout or None
    except FileNotFoundError:
        return f"command not found: {cmd}"

class NetCat:
    def __init__(self, args):
        self.args = args
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                       # можно перезапускать сервер без ожидания

    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, addr = self.socket.accept()
            print(f'> Received incoming connection from {addr[0]}:{addr[1]}')
            client_thread = threading.Thread(target=self.handle, args=(client_socket, addr))
            client_thread.start()

    def handle(self, client_socket, addr):
        if self.args.execute:
            output = execute(self.args.execute)
            output += marker
            client_socket.sendall(output.encode())
            client_socket.shutdown(socket.SHUT_WR)
            client_socket.close()

        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(7)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'Saved file {self.args.upload}'
            message += marker
            client_socket.sendall(message.encode())
            client_socket.close()

        elif self.args.command:
            cmd_buffer = b''
            client_socket.sendall(BHP)
            print(f'[<==] Sending {len(BHP)} bytes to {addr[0]}:{addr[1]}')
            while True:
                try:
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    if len(cmd_buffer):
                        print(f'[==>] Received {len(cmd_buffer)} bytes to {addr[0]}:{addr[1]}')
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.sendall(response.encode())
                        print(f"[<==] Sending {len(response)} bytes to localhost.")
                    elif response == None:
                        client_socket.sendall(b'None')
                        print(f'[==>] Received "None" to {addr[0]}:{addr[1]}')
                    cmd_buffer = b''
                except Exception as e:
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()

def main():
    parser = argparse.ArgumentParser(
        description='BHP Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
            # командная оболочка
            netcat.py -t 192.168.1.108 -p 9999 -c

            # загружаем в файл
            netcat.py -t 192.168.1.108 -p 9999 -u=mytext.txt

            # выполняем команду
            netcat.py -t 192.168.1.108 -p 9999 -e=\"cat /etc/passwd"

            # шлем текст на порт сервера
            echo 'ABC' | .netcat.py -t 192.168.2.100 -p 9999
            
            # соединяемся с сервером
            netcat.py -t 192.168.1.108 -p 9999
        '''))
    parser.add_argument('-t', '--target', default='192.168.2.100', help='specified IP')
    parser.add_argument('-p', '--port', type=int, default=9999, help='specified PORT')
    parser.add_argument('-c', '--command', action='store_true', help='command_shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-u', '--upload', help='upload file')
    args = parser.parse_args()


    nc = NetCat(args)
    nc.listen()


if __name__ == '__main__':
    main()
    

