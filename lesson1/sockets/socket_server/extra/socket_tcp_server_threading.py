import socketserver

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class EchoTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096).strip()
        print(f'Address: {self.client_address[0]}')
        print(f'Data: {data.decode()}')
        self.request.sendall(data)

if __name__ == '__main__':
    with ThreadingTCPServer(('', 6666), EchoTCPHandler) as server:
        server.serve_forever()



