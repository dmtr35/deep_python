import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('127.0.0.1', 6666))
sock.listen(5)
# блокирующий, по умолчанию (True) / не блокирующий режим (False)
sock.setblocking(False)

client, addr = sock.accept()
result = client.recv(4096)
client.close()

print('Massege:', result.decode('utf-8'))

