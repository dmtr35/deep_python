import socket

ip = '192.168.2.100'
port = 9999

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((ip, port))

client.send(b'hello from client')
res = client.recv(4096)

print(res.decode())


