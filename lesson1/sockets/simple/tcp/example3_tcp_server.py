import socket

# посмотреть числовые значения
# print(socket.AF_INET.value, socket.SOCK_STREAM.value)   # 2 1
# print(int(socket.AF_INET), int(socket.SOCK_STREAM))     # 2 1

sock = socket.socket(2, 1)
# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('127.0.0.1', 6666))
sock.listen(5)

while True:
    try:
        client, addr = sock.accept()
        print('Connect from:', addr)
    except KeyboardInterrupt:
        sock.close()
        break
    else:
        result = client.recv(4096)
        client.close()
        print('Massage:', result.decode('utf-8'))

