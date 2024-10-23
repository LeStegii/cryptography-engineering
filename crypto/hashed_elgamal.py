from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_ecdh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def derive_key_from_shared_secret(X_y, Y, info=b"handshake data"):
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=Y,
        info=info,
    ).derive(X_y)
    return derived_key


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


def main():
    # Alice
    x, X = generate_ecdh_key_pair()
    print(f"Alice Private key: {x}")
    print(f"Public key: {X}")

    # Bob
    message = "Old McDonald had a farm"
    print(f"Message: {message}")

    y, Y = generate_ecdh_key_pair()
    c0 = Y

    Y_bytes = Y.public_bytes(
        encoding=serialization.Encoding.PEM,  # PEM format
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    K_b = derive_key_from_shared_secret(y.exchange(ec.ECDH(), X), Y_bytes)
    nonce, c1 = aes_ctr_encrypt(K_b, message)

    # Alice
    c0_bytes = c0.public_bytes(
        encoding=serialization.Encoding.PEM,  # PEM format
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    K_a = derive_key_from_shared_secret(x.exchange(ec.ECDH(), c0), c0_bytes)
    message_decrypted = aes_ctr_decrypt(K_a, nonce, c1)

    print(f"Decrypted message: {message_decrypted}")


if __name__ == "__main__":
    main()
