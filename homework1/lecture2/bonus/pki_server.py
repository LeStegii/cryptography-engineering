import sys

from homework2.lecture4.x3dh_utils import generate_signature_key_pair

HOST = '127.0.0.1' if len(sys.argv) < 2 else sys.argv[1]
PORT = 25566 if len(sys.argv) < 3 else int(sys.argv[2])

sk_s, pk_s = generate_signature_key_pair()

from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class PKIRequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super(PKIRequestHandler, self).__init__(*args, **kwargs)

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')

        input_data = json.loads(post_data)
        pk_u_hex = input_data.get("pk_u", "")
        print(f"Received public key from user: {pk_u_hex}")

        pk_u_bytes = bytes.fromhex(pk_u_hex)
        cert = sk_s.sign(pk_u_bytes).hex()

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"cert": cert, "pk_s": pk_s.to_pem().hex()}).encode('utf-8'))

if __name__ == '__main__':
    server_address = (HOST, PORT)
    print(f"Server public key: {pk_s.to_pem().hex()}")
    httpd = HTTPServer(server_address, PKIRequestHandler)
    print(f"Starting server on port {HOST}:{PORT}...")
    httpd.serve_forever()

