"""Standard-library-only fixture and assertions for the isolated Linux WAN."""
import hashlib
import http.client
import http.server
import selectors
import socket
import struct
import sys
import threading

BLOB = bytes(range(256)) * 4096


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.client_address[0].encode() if self.path == '/source' else BLOB
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve():
    class V6Server(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6

    for cls, host in [(http.server.ThreadingHTTPServer, '203.0.113.10'),
                      (V6Server, '2001:db8::10')]:
        server = cls((host, 8000), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    selector = selectors.DefaultSelector()
    for family, host in [(socket.AF_INET, '203.0.113.10'),
                         (socket.AF_INET6, '2001:db8::10')]:
        for port in [9000, 53]:
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.bind((host, port))
            selector.register(s, selectors.EVENT_READ, port)
    while True:
        for event, _ in selector.select():
            s = event.fileobj
            data, address = s.recvfrom(4096)
            if event.data == 53:
                # Fixed A answer for the controlled lab.test query below.
                if len(data) < 12:
                    continue
                data = (data[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
                        + data[12:] + b'\xc0\x0c'
                        + struct.pack('!HHIH', 1, 1, 60, 4)
                        + socket.inet_aton('203.0.113.10'))
            s.sendto(data, address)


def check():
    for family, host, expected in [(socket.AF_INET, '203.0.113.10', '198.18.0.1'),
                                   (socket.AF_INET6, '2001:db8::10', 'fdc0:2::1')]:
        for path in ['/source', '/blob']:
            c = http.client.HTTPConnection(host, 8000, timeout=30)
            c.request('GET', path)
            r = c.getresponse()
            body = r.read()
            assert r.status == 200
            if path == '/source':
                assert body.decode() == expected, (host, body, expected)
            else:
                assert hashlib.sha256(body).digest() == hashlib.sha256(BLOB).digest()
            c.close()
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(10)
            s.sendto(BLOB[:1000], (host, 9000))
            assert s.recv(4096) == BLOB[:1000]
            query = struct.pack('!HHHHHH', 1234, 0x100, 1, 0, 0, 0)
            query += b'\x03lab\x04test\x00\x00\x01\x00\x01'
            s.sendto(query, (host, 53))
            response = s.recv(4096)
            assert response[:2] == query[:2]
            assert response[-4:] == socket.inet_aton('203.0.113.10')
        print('PASS', host, 'NAT source', expected, 'TCP/UDP/DNS')


if __name__ == '__main__':
    check() if '--check' in sys.argv else serve()
