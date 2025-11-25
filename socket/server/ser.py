import socket

ip = '192.168.2.100'
port = 2222

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((ip, port))
server.listen()
client, _ = server.accept()

res = client.recv(4096)
print(res.decode())
client.send(b'i now!')