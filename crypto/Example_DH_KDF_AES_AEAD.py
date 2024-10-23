""""
Install necessary packages:
pip3 install cryptography (or pip)
pip3 install pycryptodomex (or pip)

""""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, hashlib

# Generate ECDH private and public key pair
def generate_ecdh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Compute the shared secret using ECDH
def compute_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

# HKDF to derive symmetric key from shared secret
def derive_key_from_shared_secret(shared_secret, salt=None, info=b"handshake data"):
    if salt is None:
        salt = os.urandom(16)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        info=info,
    ).derive(shared_secret)
    return derived_key

# Symmetric Encryption (AES-CTR)
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

# AES-GCM encryption
def aes_gcm_encrypt(key, plaintext, associated_data):
    iv = os.urandom(12)  # GCM mode standard IV size is 96 bits (12 bytes)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # Add associated data (not encrypted but authenticated)
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    return iv, ciphertext, encryptor.tag

# AES-GCM decryption
def aes_gcm_decrypt(key, iv, ciphertext, associated_data, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # Add associated data (must match what was provided during encryption)
    decryptor.authenticate_additional_data(associated_data)

    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode()

# Main function
def main():
    # Step 1: Generate ECDH key pairs for Alice and Bob
    alice_private_key, alice_public_key = generate_ecdh_key_pair() # Alice has (a, A = g^a)
    bob_private_key, bob_public_key = generate_ecdh_key_pair() # Bob has (b, B = g^b)

    # Step 2: Compute shared secret using ECDH
    alice_shared_secret = compute_shared_secret(alice_private_key, bob_public_key) # Alice computes B^a
    bob_shared_secret = compute_shared_secret(bob_private_key, alice_public_key) # Bob computes A^b

    # Ensure both shared secrets are the same
    assert alice_shared_secret == bob_shared_secret, "Shared secrets do not match!"

    # Print the process of key exchange
    alice_public_key_printable = alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM, # PEM format
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) 
    bob_public_key_printable = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM, # PEM format
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"\nAlice and Bob is doing DHKE:\n")
    print(f"Alice ---(g^a = \n{alice_public_key_printable.decode('utf-8')})--> Bob\n")
    print(f"Alice <--(g^b = \n{bob_public_key_printable.decode('utf-8')})--- Bob\n")

    # Step 3: Derive symmetric keys using HKDF from the shared secret
    salt = bytes([0] * hashlib.sha256().digest_size) # Suppose that Alice and Bob use the same zero salt
    derived_key_alice = derive_key_from_shared_secret(alice_shared_secret, salt) # Alice computes HKDF(salt, A^b)
    derived_key_bob = derive_key_from_shared_secret(bob_shared_secret, salt) # Bob computes HKDF(salt, B^a)
    print(f"Derived Symmetric Key (hex) of Alice: {derived_key_alice.hex()}")
    print(f"Derived Symmetric Key (hex) of Bob: {derived_key_bob.hex()}")

    print("\nAES-CTR example: \n")
    
    # Step 4: Alice encrypts a long message using AES with its derived symmetric key in CTR mode
    message = "AES-CTR-----This is Alice!This is Alice!This is Alice!This is Alice!This is Alice!This is Alice!This is Alice!This is Alice!This is Alice!This is Alice!"
    nonce, ciphertext = aes_ctr_encrypt(derived_key_alice, message) # AKE-CTR includes a nonce
    print(f"Ciphertext (hex) encrypted by Alice: \n Nonce = {nonce.hex()}, \n CT = {ciphertext.hex()} \n")

    # Step 5: Bob decrypts the ciphertext
    decrypted_message = aes_ctr_decrypt(derived_key_bob, nonce, ciphertext)
    print(f"Message decrypted by Bob: {decrypted_message} \n")

    print("\nAES-GCM example: \n")

    # Step 6: Similar example using the same derived keys, but now we use AEAD (AES-GCM) instead of AES-CTR
    message = "AES-GCM-----This is Bob!This is Bob!This is Bob!This is Bob!This is Bob!This is Bob!This is Bob!This is Bob!This is Bob!This is Bob!This is Bob!This is Bob!This is Bob!"
    associated_data = f"Alice, Bob, {alice_public_key}, {bob_public_key}".encode() # Set the assiciate data as "('Alice', 'Bob', A, B)", where A and B are the pk's of ALice and Bob, respectively
    iv, ciphertext, tag = aes_gcm_encrypt(derived_key_bob, message, associated_data) # Bob encrypts its message using AEAD (AES-GCM)

    print(f"Ciphertext (hex) encrypted by Bob:\n IV = {iv.hex()},\n CT = {ciphertext.hex()},\n Tag = {tag.hex()}\n")

    decrypted_message = aes_gcm_decrypt(derived_key_alice, iv, ciphertext, associated_data, tag) # ALice decrypts the ciphertext
    print(f"Message decrypted by Alice: {decrypted_message}")

if __name__ == "__main__":
    main()
