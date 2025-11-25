import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('127.0.0.1', 6666))
sock.listen(5)
# sock.setblocking(True)
# sock.settimeout(5)
# sock.settimeout(0) # -> sock.blickeng(False)
sock.settimeout(None) # -> sock.bliking(True)

try:
    client, addr = sock.accept()
except socket.error:
    print('No connections')
# except socket.timeout:
#     print('timed out')
else:
    result = client.recv(4096)
    client.close()
    print('Message', result.decode('utf-8'))




