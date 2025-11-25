import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('192.168.2.100', 65212))

result = sock.recv(4096)
print(result.decode())

sock.close()
