import socket
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256, Hash

import utils
from homework2.lecture3.tls.HKDF import hkdf_extract, hkdf_expand

port = int(sys.argv[1]) if len(sys.argv) > 1 else 54321
client_port = int(sys.argv[2]) if len(sys.argv) > 2 else 12345
host = sys.argv[3] if len(sys.argv) > 3 else "localhost"
target_host = sys.argv[4] if len(sys.argv) > 4 else "localhost"

sock = None


def send(bytes) -> None:
    global sock
    sock.sendto(bytes, (host, client_port))


def receive() -> bytes:
    global sock
    rec, _ = sock.recvfrom(1024)
    return rec


def sha256(bytes: bytes) -> str:
    data = bytes
    digest = Hash(SHA256(), backend=default_backend())
    digest.update(data)
    hashed_bytes = digest.finalize()
    return hashed_bytes.hex()


def derive_hs(g_xy):
    ES = hkdf_extract(0, 0)
    dES = hkdf_expand(ES, sha256(b"DerivedES"))
    HS = hkdf_extract(dES, sha256(g_xy))
    return HS


def key_schedule_1(g_xy):
    HS = derive_hs(g_xy)
    K1C = hkdf_expand(HS, sha256(b"ClientKE"))
    K1S = hkdf_expand(HS, sha256(b"ServerKE"))
    return K1C, K1S


def key_schedule_2(nonce_c: bytes, X: bytes, nonce_s: bytes, Y: bytes, g_xy: bytes):
    HS = derive_hs(g_xy)
    ClientKC = hkdf_expand(HS, sha256(nonce_c + X + nonce_s + Y + b"ClientKC"))
    ServerKC = hkdf_expand(HS, sha256(nonce_c + X + nonce_s + Y + b"ServerKC"))
    K2C = hkdf_expand(HS, ClientKC)
    K2S = hkdf_expand(HS, ServerKC)
    return K2C, K2S


def key_schedule_3(nonce_c: bytes, X: bytes, nonce_s: bytes, Y: bytes, g_xy: bytes, sigma, cert_pk_s, mac_s):
    pass  # TODO


def main():
    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    print("Generating private and public key...")
    sk_s, pk_s = utils.generate_ecdh_key_pair(ec.SECP256R1())
    y = sk_s
    Y = pk_s
    cert_pk_s = utils.ecdsa_sign(pk_s, sk_s)

    print("Waiting for the client's nonce and public key...")
    nonce_c = receive()
    X = receive()

    print("Received nonce and public key from the client!")

    print("Generating keys...")

    K1C, K1S = key_schedule_1(utils.to_bytes(X))

    print("Generating nonce (32 random bytes)...")
    nonce_s = b"B" * 32

    print("Sending nonce and public key to the client...")

    send(nonce_s)
    send(utils.to_bytes(Y))


if __name__ == "__main__":
    main()
