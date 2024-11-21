import socket

from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import utils

HOST = '127.0.0.1'
PORT = 65432


def mitm_server():
    g = ec.SECP256R1()
    salt = bytes([0] * hashes.SHA256().digest_size)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(2)
        print("MITM Server is running...")

        # Receive public key (X) from Alice
        alice_conn, _ = server_socket.accept()
        print("Alice connected.")
        alice_data = alice_conn.recv(4096)
        X = serialization.load_pem_public_key(alice_data)
        print("Alice's public key received.")

        # Receive public key (Y) from Bob
        bob_conn, _ = server_socket.accept()
        print("Bob connected.")
        bob_data = bob_conn.recv(4096)
        Y = serialization.load_pem_public_key(bob_data)
        print("Bob's public key received.")

        # Generate two key pairs
        x1, X1 = utils.generate_ecdh_key_pair(g)
        y1, Y1 = utils.generate_ecdh_key_pair(g)

        # Send forged public key (Y1) to Alice
        alice_conn.sendall(utils.to_bytes(Y1))
        print("MITM sent forged public key to Alice.")

        # Send forged public key (X1) to Bob
        bob_conn.sendall(utils.to_bytes(X1))
        print("MITM sent forged public key to Bob.")

        # Compute shared secrets (X^y1 and Y^x1) for the attacker
        secret_attacker_alice = y1.exchange(ec.ECDH(), X)
        K_attacker_alice = utils.derive_key_from_shared_secret(secret_attacker_alice, salt)

        secret_attacker_bob = x1.exchange(ec.ECDH(), Y)
        K_attacker_bob = utils.derive_key_from_shared_secret(secret_attacker_bob, salt)

        print("MITM's keys computed.")

        print(f"K'_Alice: {K_attacker_alice}")
        print(f"K'_Bob: {K_attacker_bob}")

        # Forward encrypted message
        message_data = bob_conn.recv(4096)
        print("MITM received encrypted message from Bob.")
        nonce, cipher_bob_to_alice = message_data[:8], message_data[8:]
        decrypted = aes_ctr_decrypt(K_attacker_bob, nonce, cipher_bob_to_alice)
        print(f"MITM decrypted Bob's message: {decrypted}")

        # Re-encrypt for Alice
        nonce1, cipher_bob_to_alice1 = aes_ctr_encrypt(K_attacker_alice, decrypted)
        alice_conn.sendall(nonce1 + cipher_bob_to_alice1)
        print("MITM re-encrypted message and sent to Alice.")

        alice_conn.close()
        bob_conn.close()


def aes_ctr_encrypt(derived_key, plaintext):
    cipher = AES.new(derived_key, AES.MODE_CTR)
    nonce = cipher.nonce  # CTR mode uses a nonce instead of an IV
    ciphertext = cipher.encrypt(plaintext.encode())  # No padding needed in CTR
    return nonce, ciphertext


# Symmetric Decryption (AES-CTR)
def aes_ctr_decrypt(derived_key, nonce, ciphertext):
    cipher = AES.new(derived_key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()


if __name__ == '__main__':
    mitm_server()
