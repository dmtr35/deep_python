import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('127.0.0.1', 6666))
sock.listen(5)
sock.setblocking(False)

while True:
    try:
        client, addr = sock.accept()
    except socket.error:
        print('no clients')
    except KeyboardInterrupt:
        break
    else:
        client.setblocking(True)            # устанавливаем клиенту блокирующий режим
        result = client.recv(4096)
        client.close()
        print('Massege: ', result.decode('utf-8'))