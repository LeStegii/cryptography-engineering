import os
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    EllipticCurvePrivateKey, SECP256R1,
)
from ecdsa import SigningKey
from ecdsa.ellipticcurve import Point

import utils
from homework2.lecture3.tls.HKDF import hkdf_extract
from homework3.lecture9 import Hash2Curve

H = utils.sha256


# Utility to generate a random scalar for the elliptic curve group
def random_element() -> Point:
    return Hash2Curve.gen_random_point()

def random_z_q() -> int:
    return int.from_bytes(os.urandom(32)) % Hash2Curve.q

def power(base: Point, exponent: int) -> Point:
    return exponent * base

def h(string: bytes) -> Point:
    return Hash2Curve.hash_to_curve(string)


def inverse(x: int) -> int:
    return pow(x, -1, Hash2Curve.n)


def KDF(rw: bytes) -> bytes:
    return hkdf_extract(salt=None, input_key_material=rw)


def AKE_KeyGen() -> Tuple[EllipticCurvePublicKey, EllipticCurvePrivateKey]:
    pair = utils.generate_ecdh_key_pair(SECP256R1)
    return pair[1], pair[0]


def AEAD_encode(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    return utils.aes_gcm_encrypt(key, plaintext, b"")


def AEAD_decode(key: bytes, ciphertext: bytes, iv: bytes, tag: bytes) -> bytes:
    return utils.aes_gcm_decrypt(key, iv, ciphertext, b"", tag)
