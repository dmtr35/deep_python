# with operator
import socket

# __enter__ / __exit__
# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    print('6666 is bind')
    sock.bind(('127.0.0.1', 6666))

    while True:
        result = sock.recv(4096)
        print('Message:', result.decode('utf-8'))
        
