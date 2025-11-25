import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 6666))

while True:
    try:
        result = sock.recv(4096)
    except KeyboardInterrupt:
        sock.close()
        break
    else:
        print('Message: ', result.decode('utf-8'))