import json
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


def encode_message(message: dict[str, str | SigningKey | VerifyingKey | bytes | dict]) -> bytes:
    dictionary = {}
    for key, value in message.items():
        if isinstance(value, str):
            dictionary[key + "||STR"] = value.encode().hex()
        elif isinstance(value, SigningKey):
            dictionary[key + "||SK"] = value.to_pem().hex()
        elif isinstance(value, VerifyingKey):
            dictionary[key + "||VK"] = value.to_pem().hex()
        elif isinstance(value, bytes):
            dictionary[key + "||BYTE"] = value.hex()
        elif isinstance(value, dict):
            dictionary[key + "||DICT"] = encode_message(value).hex()
        else:
            raise ValueError(f"Unsupported type: {type(value)}")

    return json.dumps(dictionary).encode()


def decode_message(encoded: bytes) -> dict[str, str | SigningKey | VerifyingKey | bytes | dict]:
    decoded = json.loads(encoded.decode())
    decoded_message = {}
    for key, value in decoded.items():
        key, type_ = key.split("||")
        if type_ == "STR":
            decoded_message[key] = bytes.fromhex(value).decode()
        elif type_ == "SK":
            decoded_message[key] = SigningKey.from_pem(bytes.fromhex(value).decode())
        elif type_ == "VK":
            decoded_message[key] = VerifyingKey.from_pem(bytes.fromhex(value).decode())
        elif type_ == "BYTE":
            decoded_message[key] = bytes.fromhex(value)
        elif type_ == "DICT":
            decoded_message[key] = decode_message(bytes.fromhex(value))
        else:
            raise ValueError(f"Unsupported type: {type_}")

    return decoded_message

