import socket
import select

PORT = 6666
BUF = 4096
TIMEOUT = 5.0  # seconds

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# allow reuse (helpful when restarting server quickly)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# bind to all interfaces so we can receive from any IP
sock.bind(('0.0.0.0', PORT))
print(f"Listening UDP on 0.0.0.0:{PORT} (timeout {TIMEOUT}s)")

try:
    # wait for readability with timeout
    r, _, _ = select.select([sock], [], [], TIMEOUT)
    if not r:
        print("No data received (timeout).")
    else:
        data, addr = sock.recvfrom(BUF)
        # decode safely
        text = data.decode('utf-8', errors='replace')
        print(f"Received {len(data)} bytes from {addr}: {text!r}")
finally:
    sock.close()
    print("Socket closed.")
