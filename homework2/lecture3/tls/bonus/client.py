import socket
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import VerifyingKey

from homework2.lecture3.tls.tls_utils import *
from utils import ecdsa_verify

port = int(sys.argv[1]) if len(sys.argv) > 1 else 12345
target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 54321
host = sys.argv[3] if len(sys.argv) > 3 else "localhost"
target_host = sys.argv[4] if len(sys.argv) > 4 else "localhost"

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

    # The certificate is usually hardcoded in the client
    print("Waiting for the server's certificate...")
    pk_ca = VerifyingKey.from_der(receive())

    print("Sending nonce and public key to the server...")
    send(nonce_c)
    send(utils.to_bytes(X))

    print("Waiting for the server's nonce and public key...")
    nonce_s = receive()
    Y = utils.from_bytes(receive())
    pk_s = VerifyingKey.from_der(receive())
    Y_x = x.exchange(ec.ECDH(), Y)

    print("Generating keys (1)...")
    K1C, K1S = key_schedule_1(Y_x)

    print("Generating keys (2)...")
    K2C, K2S = key_schedule_2(nonce_c, X, nonce_s, Y, Y_x)

    print("Decrypting message...")
    iv = receive()
    cipher = receive()
    tag = receive()
    cert_pk_s, sigma_s, mac_s = aes_gcm_decrypt(K1S, iv, cipher, utils.to_bytes(Y), tag).split(b"$$$")
    _, sigma_ca = cert_pk_s.split(b"|||")

    print("Generating keys (3)...")
    K3C, K3S = key_schedule_3(nonce_c, utils.to_bytes(X), nonce_s, utils.to_bytes(Y), Y_x, sigma_s, cert_pk_s, mac_s)

    print("Verifying certificates, signatures and macs...")

    if not ecdsa_verify(sigma_ca, utils.to_bytes(Y), pk_ca):
        print("Invalid certificate!")
        return

    sha = sha256(nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + cert_pk_s)

    if not ecdsa_verify(sigma_s, sha, pk_s):
        print("Invalid signature!")
        return

    if not hmac_verify(K2S, nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + sigma_s + cert_pk_s + b"ServerMAC", mac_s):
        print("Invalid mac!")
        return

    print("All checks passed!")

    print("Calculating mac_c...")
    mac_c = hmac_mac(K2C, nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + sigma_s + cert_pk_s + b"ClientMAC")

    print("Sending mac_c to the server using aes_gcm...")
    iv_c, cipher_c, tag_c = aes_gcm_encrypt(K1C, mac_c, utils.to_bytes(Y))

    send(iv_c)
    send(cipher_c)
    send(tag_c)

    print("Connection established!")
    print("K3C:", K3C)
    print("K3S:", K3S)


if __name__ == "__main__":
    main()
