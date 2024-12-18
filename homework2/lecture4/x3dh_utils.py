from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import NIST256p as CURVE
from ecdsa import SigningKey, VerifyingKey


def generate_ecdsa_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def generate_signature_key_pair() -> Tuple[SigningKey, VerifyingKey]:
    sk = SigningKey.generate(CURVE)
    vk = sk.get_verifying_key()
    return sk, vk

SPLIT = b"|$|$|$|"