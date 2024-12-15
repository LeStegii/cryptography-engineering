import os
import socket
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import NIST256p as CURVE
from ecdsa import SigningKey

import utils
from homework2.lecture3.tls.tls_utils import aes_gcm_encrypt, key_schedule_1, sigma_sign, key_schedule_2, hmac_mac, \
    key_schedule_3, aes_gcm_decrypt, hmac_verify

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


sk_ca = SigningKey.generate(CURVE)
pk_ca = sk_ca.get_verifying_key()

sk_s = SigningKey.generate(CURVE)
pk_s = sk_s.get_verifying_key()


def main():
    global sock

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    print("Generating private and public key...")
    y, Y = utils.generate_ecdh_key_pair(ec.SECP256R1())
    sigma_ca = utils.ecdsa_sign(utils.to_bytes(Y), sk_ca)
    cert_pk_s = utils.to_bytes(Y) + b"|||" + sigma_ca + b"|||" + pk_ca.to_der()

    print("Sending certificate to the client...")
    send(cert_pk_s)

    print("Waiting for the client's nonce and public key...")
    nonce_c = receive()
    X = utils.from_bytes(receive())

    print("Generating nonce (32 random bytes)...")
    nonce_s = os.urandom(32)

    print("Sending nonce and public key to the client...")
    send(nonce_s)
    send(utils.to_bytes(Y))

    print("Generating keys (1)...")
    X_y = y.exchange(ec.ECDH(), X)
    K1C, K1S = key_schedule_1(X_y)

    print("Generating sigma...")
    sigma_s = sigma_sign(sk_s, nonce_c, X, nonce_s, Y, cert_pk_s)

    print("Generating keys (2)...")
    K2C, K2S = key_schedule_2(nonce_c, X, nonce_s, Y, X_y)

    print("Generating mac_s...")
    mac_s = hmac_mac(K2S, nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + sigma_s + cert_pk_s + b"ServerMAC")

    print("Generating keys (3)...")
    K3C, K3S = key_schedule_3(nonce_c, utils.to_bytes(X), nonce_s, utils.to_bytes(Y), X_y, sigma_s, cert_pk_s, mac_s)

    print("Sending cert, sigma and mac_s to the client using aes_gcm...")
    iv, cipher, tag = aes_gcm_encrypt(K1S, cert_pk_s + b"$$$" + sigma_s + b"$$$" + mac_s, utils.to_bytes(Y))
    send(iv)
    send(cipher)
    send(tag)

    print("Waiting for the client to send its mac the connection...")
    iv_c = receive()
    cipher_c = receive()
    tag_c = receive()

    print("Decrypting the client's mac...")
    mac_c = aes_gcm_decrypt(K1C, iv_c, cipher_c, utils.to_bytes(Y), tag_c)

    print("Verifying the client's mac...")
    if not hmac_verify(K2C, nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + sigma_s + cert_pk_s + b"ClientMAC", mac_c):
        print("Invalid mac!")
        return

    print("Connection established!")
    print("K3C:", K3C)
    print("K3S:", K3S)


if __name__ == "__main__":
    main()
