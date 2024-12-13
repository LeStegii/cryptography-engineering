import socket
import sys

from cryptography.hazmat.primitives.asymmetric import ec

import utils
from homework2.lecture3.tls.tls_utils import *

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
    nonce_c = os.urandom(32)

    print("Waiting for the server's certificate...")
    cert_pk_s = receive()
    Y, sigma_ca = cert_pk_s.split(b"|||")
    print("Received certificate from the server!")

    print("Sending nonce and public key to the server...")

    send(nonce_c)
    send(utils.to_bytes(X))

    print("Waiting for the server's nonce and public key...")

    nonce_s = receive()
    Y = utils.from_bytes(receive())

    Y_x = x.exchange(ec.ECDH(), Y)

    print("Received nonce and public key from the server!")

    print("Generating keys (1)...")

    K1C, K1S = key_schedule_1(Y_x)

    print("Generating sigma...")
    #sigma = sigma_sign(sk_s, nonce_c, X, nonce_s, Y, cert_pk_s)

    print("Generating keys (2)...")

    K2C, K2S = key_schedule_2(nonce_c, X, nonce_s, Y, Y_x)

    print("Decrypting message...")
    iv = receive()
    cipher = receive()
    tag = receive()

    print(iv)
    print(cipher)
    print(tag)

    cert_pk_s_2, sigma, mac_s = aes_gcm_decrypt(K1S, iv, cipher, utils.to_bytes(Y), tag).split(b"$$$")

    print("Generating keys (3)...")
    K3C, K3S = key_schedule_3(nonce_c, X, nonce_s, Y, Y_x, sigma_ca, cert_pk_s, mac_s)

    print("Verifying certificates and macs...")

    if not cert_pk_s_2 == cert_pk_s:
        print("Certificate mismatch!")
        return

    #if not utils.ecdsa_verify(pk_ca, pk_s, sigma):
    #    print("Invalid certificate!")
    #    return

    if not hmac_verify(K2S, nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + sigma + b"ServerMAC", mac_s):
        print("Invalid mac!")
        return

    print("All checks passed!")

    print("Calculating mac_c...")

    mac_c = hmac_mac(K2S, nonce_c, X, nonce_s, Y, sigma, cert_pk_s, b"ClientMAC")

    print("Sending mac_c to the server using aes_gcm...")
    iv_c, cipher_c, tag_c = aes_gcm_encrypt(K1C, mac_c, Y)

    send(iv_c)
    send(cipher_c)
    send(tag_c)


if __name__ == "__main__":
    main()
