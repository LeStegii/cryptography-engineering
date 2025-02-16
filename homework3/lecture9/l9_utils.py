import os

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
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

def power_ec(base: EllipticCurvePublicKey, exponent: EllipticCurvePrivateKey) -> int:
    return base.public_numbers().y * exponent.private_numbers().private_value

def h(string: bytes) -> Point:
    return Hash2Curve.hash_to_curve(string)


def inverse(x: int) -> int:
    return pow(x, -1, Hash2Curve.n)


def KDF(rw: bytes) -> bytes:
    return hkdf_extract(salt=None, input_key_material=rw)


def AEAD_encode(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    return utils.aes_gcm_encrypt(key, plaintext, b"")


def AEAD_decode(key: bytes, ciphertext: bytes, iv: bytes, tag: bytes) -> bytes:
    return utils.aes_gcm_decrypt(key, iv, ciphertext, b"", tag)


def AKE_KeyGen() -> tuple[Point, int]:
    private_key = random_z_q()
    public_key = power(Hash2Curve.g, private_key)

    return Point.from_bytes(Hash2Curve.P256.curve, public_key.to_bytes()), private_key

def HMQV_KClient(a: int, x: int, X: Point, B: Point, Y: Point, client: str, server: str):
    d = bytes_to_int(utils.sha256(point_to_bytes(X) + server.encode())) % Hash2Curve.q
    e = bytes_to_int(utils.sha256(point_to_bytes(Y) + client.encode())) % Hash2Curve.q

    ss = power(power(B, e) + Y, (x + d * a) % Hash2Curve.q)

    SK = hkdf_extract(salt=None, input_key_material=ss.to_bytes())
    return SK

def HMQV_KServer(b: int, y: int, Y: Point, A: Point, X: Point, client: str, server: str):
    d = bytes_to_int(utils.sha256(point_to_bytes(X) + server.encode())) % Hash2Curve.q
    e = bytes_to_int(utils.sha256(point_to_bytes(Y) + client.encode())) % Hash2Curve.q

    ss = power(power(A, d) + X, (y + e * b) % Hash2Curve.q)

    SK = hkdf_extract(salt=None, input_key_material=ss.to_bytes())
    return SK

def mult_points(P: Point, Q: Point) -> Point:
    return P + Q

def point_to_bytes(P: Point) -> bytes:
    return P.x().to_bytes(32, byteorder="big")

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes(byteorder="big", length=(x.bit_length() + 7) // 8)

def bytes_to_int(x: bytes) -> int:
    return int.from_bytes(x, byteorder="big")