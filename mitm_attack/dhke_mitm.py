import hashlib

from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec

import utils


def main():
    g = ec.SECP256R1()
    salt = bytes([0] * hashlib.sha256().digest_size)

    # Alice generates x and X (private and public key)
    x, X = utils.generate_ecdh_key_pair(g)

    # Bob generates y and Y (private and public key)
    y, Y = utils.generate_ecdh_key_pair(g)

    # Attacker generates two new key pairs, sends Y1 to Alice and X1 to Bob
    x1, X1 = utils.generate_ecdh_key_pair(g)
    y1, Y1 = utils.generate_ecdh_key_pair(g)

    # Alice computes the shared secret with Y1
    secret_alice = x.exchange(ec.ECDH(), Y1)
    K_alice = utils.derive_key_from_shared_secret(secret_alice, salt)

    # Bob computes the shared secret with X1
    secret_bob = y.exchange(ec.ECDH(), X1)
    K_bob = utils.derive_key_from_shared_secret(secret_bob, salt)


    # Attacker computes the shared secrets
    secret_attacker_alice = y1.exchange(ec.ECDH(), X)
    K_attacker_alice = utils.derive_key_from_shared_secret(secret_attacker_alice, salt)
    secret_attacker_bob = x1.exchange(ec.ECDH(), Y)
    K_attacker_bob = utils.derive_key_from_shared_secret(secret_attacker_bob, salt)

    print(f"Alice and Bob have the same key? {K_alice == K_bob} (should be False)")
    print(f"Alice and Attacker have the same key? {K_alice == K_attacker_alice} (should be True)")
    print(f"Bob and Attacker have the same key? {K_bob == K_attacker_bob} (should be True)")

    # Bob encrypts a message with the shared key
    message = "Hello Alice!"
    print(f"Message from Bob: {message}")
    nonce, cipher_bob_to_alice = aes_ctr_encrypt(K_bob, message)

    # Attacker decrypts the message
    decrypted = aes_ctr_decrypt(K_attacker_bob, nonce, cipher_bob_to_alice)
    print(f"Message decrypted by the attacker: {decrypted}")

    # Attacker encrypts the message with the shared key
    nonce1, cipher_bob_to_alice1 = aes_ctr_encrypt(K_attacker_alice, decrypted)

    # Alice decrypts the message
    message1 = aes_ctr_decrypt(K_alice, nonce1, cipher_bob_to_alice1)
    print(f"Message decrypted by Alice: {message1}")



    # Alice encrypts the message with the shared key



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

if __name__ == "__main__":
    main()