import socket

target_host = "127.0.0.1"
target_port = 9997

# создаем обьект сокета (F_INET - стандартные IPv4, DGRAM - будет работать по UDP)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# отправляем данные
client.sendto(b"AAABBBCCC", (target_host, target_port))

# принимаем данные
data, addr = client.recvfrom(4096)

print("res:", data.decode())
client.close()



