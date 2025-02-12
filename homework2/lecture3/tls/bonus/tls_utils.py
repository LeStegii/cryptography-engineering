import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA3_512

import utils
from homework2.lecture3.tls.bonus.HKDF import hkdf_extract, hkdf_expand


def aes_gcm_encrypt(key, plaintext, associated_data):
    """Double-encrypt the plaintext using AES-GCM with a 512-bit key."""
    key1, key2 = key[:32], key[32:]

    # First encryption
    iv1 = os.urandom(12)
    encryptor1 = Cipher(
        algorithms.AES(key1),
        modes.GCM(iv1),
        backend=default_backend()
    ).encryptor()
    encryptor1.authenticate_additional_data(associated_data)
    ciphertext1 = encryptor1.update(plaintext) + encryptor1.finalize()

    # Second encryption
    iv2 = os.urandom(12)
    encryptor2 = Cipher(
        algorithms.AES(key2),
        modes.GCM(iv2),
        backend=default_backend()
    ).encryptor()
    encryptor2.authenticate_additional_data(associated_data)
    ciphertext2 = encryptor2.update(ciphertext1) + encryptor2.finalize()

    return iv1, iv2, ciphertext2, encryptor1.tag, encryptor2.tag

def aes_gcm_decrypt(key, iv1, iv2, ciphertext, associated_data, tag1, tag2):
    """Double-decrypt the ciphertext using AES-GCM with a 512-bit key."""
    key1, key2 = key[:32], key[32:]

    # First decryption (reverse order)
    decryptor2 = Cipher(
        algorithms.AES(key2),
        modes.GCM(iv2, tag2),
        backend=default_backend()
    ).decryptor()
    decryptor2.authenticate_additional_data(associated_data)
    intermediate_plaintext = decryptor2.update(ciphertext) + decryptor2.finalize()

    # Second decryption
    decryptor1 = Cipher(
        algorithms.AES(key1),
        modes.GCM(iv1, tag1),
        backend=default_backend()
    ).decryptor()
    decryptor1.authenticate_additional_data(associated_data)
    plaintext = decryptor1.update(intermediate_plaintext) + decryptor1.finalize()

    return plaintext



def sha3_512(bytes: bytes) -> bytes:
    data = bytes
    digest = Hash(SHA3_512(), backend=default_backend())
    digest.update(data)
    hashed_bytes = digest.finalize()
    return hashed_bytes


def derive_hs(g_xy):
    ES = hkdf_extract(bytes(0), bytes(0))
    dES = hkdf_expand(ES, sha3_512(b"DerivedES"))
    HS = hkdf_extract(dES, sha3_512(g_xy))
    return HS


def key_schedule_1(g_xy):
    HS = derive_hs(g_xy)
    K1C = hkdf_expand(HS, sha3_512(b"ClientKE"))
    K1S = hkdf_expand(HS, sha3_512(b"ServerKE"))
    return K1C, K1S


def key_schedule_2(nonce_c: bytes, X: bytes, nonce_s: bytes, Y: bytes, g_xy: bytes):
    HS = derive_hs(g_xy)
    ClientKC = sha3_512(nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + b"ClientKC")
    ServerKC = sha3_512(nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + b"ServerKC")
    K2C = hkdf_expand(HS, ClientKC)
    K2S = hkdf_expand(HS, ServerKC)
    return K2C, K2S


def key_schedule_3(nonce_c: bytes, X: bytes, nonce_s: bytes, Y: bytes, g_xy: bytes, sigma, cert_pk_s, mac_s):
    HS = derive_hs(g_xy)
    dHS = hkdf_expand(HS, sha3_512(b"DerivedHS"))
    MS = hkdf_extract(dHS, bytes(0))
    ClientSKH = sha3_512(nonce_c + X + nonce_s + Y + sigma + cert_pk_s + mac_s + b"ClientEncK")
    ServerSKH = sha3_512(nonce_c + X + nonce_s + Y + sigma + cert_pk_s + mac_s + b"ServerEncK")
    K3C = hkdf_expand(MS, ClientSKH)
    K3S = hkdf_expand(MS, ServerSKH)
    return K3C, K3S


def sigma_sign(sk, nonce_c, X, nonce_s, Y, cert_pk) -> bytes:
    return utils.ecdsa_sign(sha3_512(nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + cert_pk), sk)


def hmac_mac(K, message) -> bytes:
    h = hmac.HMAC(K, hashes.SHA256(), default_backend())
    h.update(message)
    return h.finalize()


def hmac_verify(K, message, mac) -> bool:
    h = hmac.HMAC(K, hashes.SHA256(), default_backend())
    h.update(message)
    try:
        h.verify(mac)
        return True
    except Exception:
        return False
