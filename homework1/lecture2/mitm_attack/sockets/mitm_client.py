import socket

from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
import utils

HOST = '127.0.0.1'
PORT = 65432

def client(role):
    g = ec.SECP256R1()
    salt = bytes([0] * hashes.SHA256().digest_size)

    # Generate private and public key
    private_key, public_key = utils.generate_ecdh_key_pair(g)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        client_socket.sendall(utils.to_bytes(public_key))

        # Receive public key from server
        other_public_key_data = client_socket.recv(4096)
        other_public_key = serialization.load_pem_public_key(other_public_key_data)

        # Compute shared secret
        secret = private_key.exchange(ec.ECDH(), other_public_key)
        shared_key = utils.derive_key_from_shared_secret(secret, salt)
        print(f"{role} computed shared key, waiting for the other party...")
        print(f"Shared key: {shared_key}")


        if role == 'Bob':
            # Encrypt and send a message to Alice
            message = "Hello Alice!"
            nonce, ciphertext = aes_ctr_encrypt(shared_key, message)
            client_socket.sendall(nonce + ciphertext)
            print(f"Bob sent: {message}")

        elif role == 'Alice':
            # Receive and decrypt the message
            message_data = client_socket.recv(4096)
            nonce, ciphertext = message_data[:8], message_data[8:]
            decrypted_message = aes_ctr_decrypt(shared_key, nonce, ciphertext)
            print(f"Alice received: {decrypted_message}")


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
    import sys
    role = sys.argv[1]  # Pass "Alice" or "Bob" as argument
    client(role)
