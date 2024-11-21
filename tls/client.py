import socket
import sys

from cryptography.hazmat.primitives.asymmetric import ec

import utils

port = int(sys.argv[2]) if len(sys.argv) > 2 else 12345
target_port = int(sys.argv[3]) if len(sys.argv) > 3 else 54321
host = sys.argv[4] if len(sys.argv) > 4 else "localhost"
target_host = sys.argv[5] if len(sys.argv) > 4 else "localhost"

sock = None

def send(bytes) -> None:
    global sock
    sock.sendto(bytes, (host, target_port))

def receive() -> bytes:
    global sock
    rec, _ = sock.recvfrom(1024)
    return rec

def main():
    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    print("Generating private and public key...")
    x, X = utils.generate_ecdh_key_pair(ec.SECP256R1())

    print("Generating nonce (32 random bytes)...")
    nonce_c = b"A" * 32

    print("Sending nonce and public key to the server...")

    send(nonce_c)
    send(utils.to_bytes(X))

    print("Waiting for the server's nonce and public key...")

    nonce_s = receive()
    Y = receive()

    print("Received nonce and public key from the server!")


if __name__ == "__main__":
    main()
