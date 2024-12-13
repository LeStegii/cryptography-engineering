import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256, Hash

import utils
from homework2.lecture3.tls.HKDF import hkdf_extract, hkdf_expand


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
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

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

    return plaintext


def sha256(bytes: bytes) -> bytes:
    data = bytes
    digest = Hash(SHA256(), backend=default_backend())
    digest.update(data)
    hashed_bytes = digest.finalize()
    return hashed_bytes


def derive_hs(g_xy):
    ES = hkdf_extract(bytes(0), bytes(0))
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
    ClientKC = hkdf_expand(HS, sha256(nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + b"ClientKC"))
    ServerKC = hkdf_expand(HS, sha256(nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + b"ServerKC"))
    K2C = hkdf_expand(HS, ClientKC)
    K2S = hkdf_expand(HS, ServerKC)
    return K2C, K2S


def key_schedule_3(nonce_c: bytes, X: bytes, nonce_s: bytes, Y: bytes, g_xy: bytes, sigma, cert_pk_s, mac_s):
    HS = derive_hs(g_xy)
    dHS = hkdf_expand(HS, sha256(b"DerivedHS"))
    MS = hkdf_extract(dHS, bytes(0))
    ClientSKH = sha256(nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + sigma + cert_pk_s + mac_s + b"ClientEncK")
    ServerSKH = sha256(nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + sigma + cert_pk_s + mac_s + b"ServerEncK")
    K3C = hkdf_expand(MS, ClientSKH)
    K3S = hkdf_expand(MS, ServerSKH)
    return K3C, K3S


def sigma_sign(sk, nonce_c, X, nonce_s, Y, cert_pk) -> bytes:
    return utils.ecdsa_sign(sha256(nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + cert_pk), sk)


def hmac_mac(K, nonce_c, X, nonce_s, Y, sigma, cert_pk_s, message) -> bytes:
    h = hmac.HMAC(K, hashes.SHA256(), default_backend())
    h.update(nonce_c + utils.to_bytes(X) + nonce_s + utils.to_bytes(Y) + sigma + cert_pk_s + message)
    return h.finalize()


def hmac_verify(K, message, mac) -> bool:
    h = hmac.HMAC(K, hashes.SHA256(), default_backend())
    h.update(message)
    try:
        h.verify(mac)
        return True
    except Exception:
        return False
