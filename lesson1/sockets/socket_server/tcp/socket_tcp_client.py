import socket


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 6666))
sock.sendall(b'Test massege')

# result = sock.recv(4096)
# print('Response:', result.decode('utf-8'))
sock.close()