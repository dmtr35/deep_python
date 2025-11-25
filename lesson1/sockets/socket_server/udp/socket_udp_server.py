import socketserver

class EchoUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        print(f'Addres: {self.client_address[0]}')
        print(f'Data: {data.decode()}')
        socket.sendto(data, self.client_address)

if __name__ in '__main__':
    with socketserver.UDPServer(('0', 6666), EchoUDPHandler) as server:
        server.serve_forever()
        