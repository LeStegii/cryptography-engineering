import json
import os
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ecdsa import NIST256p as CURVE, ECDH
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


def power(power: SigningKey, base: VerifyingKey):
    ecdh = ECDH(CURVE)
    ecdh.load_private_key(power)
    ecdh.load_received_public_key(base)
    return ecdh.generate_sharedsecret_bytes()


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
