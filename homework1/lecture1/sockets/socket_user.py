import hashlib
import socket
import sys
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import utils

name = sys.argv[1] if len(sys.argv) > 1 else "Alice"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 12345
target_port = int(sys.argv[3]) if len(sys.argv) > 3 else 54321
host = sys.argv[4] if len(sys.argv) > 4 else "localhost"
target_host = sys.argv[5] if len(sys.argv) > 4 else "localhost"

x, X = utils.generate_ecdh_key_pair(ec.SECP256R1())

waiting_for_public_key = False

def listen_for_messages(sock):
    global waiting_for_public_key
    while True:
        data, _ = sock.recvfrom(1024)
        if data:
            print("Received public key!")
            salt = bytes([0] * hashlib.sha256().digest_size)
            Y = data
            Y = serialization.load_pem_public_key(Y)
            Y_x = x.exchange(ec.ECDH(), Y)
            derived_key = utils.derive_key_from_shared_secret(Y_x, salt)
            print(f"Derived key: {derived_key}")
            if not waiting_for_public_key:
                # Respond the message
                sock.sendto(utils.to_bytes(X), (host, target_port))
            waiting_for_public_key = False

def main():
    global waiting_for_public_key

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    listener_thread = threading.Thread(target=listen_for_messages, args=(sock,))
    listener_thread.daemon = True
    listener_thread.start()

    print("Press Enter to send your public key...")

    while True:
        input()
        waiting_for_public_key = True
        sock.sendto(utils.to_bytes(X), (host, target_port))

if __name__ == "__main__":
    main()
