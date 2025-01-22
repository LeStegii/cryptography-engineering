from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    EllipticCurvePrivateKey,
)
from ecdsa import SigningKey

import utils

H = utils.sha256

G = ec.SECP256R1()  # Equivalent to NIST256p


# Utility to generate a random scalar for the elliptic curve group
def random_element() -> int:
    return None


def h(m: bytes) -> SigningKey:
    return None


def inverse(x: SigningKey) -> SigningKey:
    return None


def KDF(rw: bytes) -> bytes:
    return None


def AKE_KeyGen() -> (EllipticCurvePublicKey, EllipticCurvePrivateKey):
    return None


def AEAD_encode(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    return utils.aes_gcm_encrypt(key, plaintext, b"")


def AEAD_decode(key: bytes, ciphertext: bytes, iv: bytes, tag: bytes) -> bytes:
    return utils.aes_gcm_decrypt(key, iv, ciphertext, b"", tag)
