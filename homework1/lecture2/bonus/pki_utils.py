from typing import Tuple

from ecdsa import NIST256p as CURVE, VerifyingKey, SigningKey


def generate_signature_key_pair() -> Tuple[SigningKey, VerifyingKey]:
    sk = SigningKey.generate(CURVE)
    vk = sk.get_verifying_key()
    return sk, vk
