# Generate ECDH private and public key pair
import hashlib
import json
import os
# Use SHA256 as the hash function used in DSA
from hashlib import sha256 as HASH_FUNC

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ecdsa import util, VerifyingKey, SigningKey, ECDH  # pip install ecdsa


# Use the curve P256, also known as SECP256R1, see https://neuromancer.sk/std/nist/P-256


def generate_ecdh_key_pair(group):
    private_key = ec.generate_private_key(group)
    public_key = private_key.public_key()
    return private_key, public_key


# Compute the shared secret using ECDH
def compute_ecdh_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret


def to_bytes(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,  # PEM format
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def from_bytes(key_bytes):
    return serialization.load_pem_public_key(
        key_bytes,
        backend=default_backend()
    )


# HKDF to derive symmetric key from shared secret
def derive_key_from_shared_secret(shared_secret, salt=None, info=b"handshake data"):
    if salt is None:
        salt = os.urandom(16)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        info=info,
    ).derive(shared_secret)
    return derived_key


def printable_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,  # PEM format
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def ecdsa_sign(message, private_key, nonce=None):
    signature = None
    if nonce:  # If the nonce is explicitly specified
        signature = private_key.sign(
            message,
            k=nonce,
            hashfunc=HASH_FUNC,
            sigencode=util.sigencode_der
        )
    else:
        signature = private_key.sign(
            message,
            hashfunc=HASH_FUNC,
            sigencode=util.sigencode_der
        )
    return signature


# Function to verify ECDSA signature
def ecdsa_verify(signature, message, public_key):
    try:
        is_valid = public_key.verify(
            signature,
            message,
            hashfunc=HASH_FUNC,
            sigdecode=util.sigdecode_der
        )
        return is_valid
    except:
        return False


def encode_message(message: dict[str, str | SigningKey | VerifyingKey | EllipticCurvePrivateKey | EllipticCurvePublicKey | bytes | dict | int | None]) -> bytes:
    dictionary = {}
    for key, value in message.items():
        if value is None:
            dictionary[key + "||NONE"] = "NONE".encode().hex()
        if isinstance(value, str):
            dictionary[key + "||STR"] = value.encode().hex()
        elif isinstance(value, SigningKey):
            dictionary[key + "||SK"] = value.to_pem().hex()
        elif isinstance(value, VerifyingKey):
            dictionary[key + "||VK"] = value.to_pem().hex()
        elif isinstance(value, EllipticCurvePrivateKey):
            dictionary[key + "||ECSK"] = value.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).hex()
        elif isinstance(value, EllipticCurvePublicKey):
            dictionary[key + "||ECPK"] = value.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex()
        elif isinstance(value, bytes):
            dictionary[key + "||BYTE"] = value.hex()
        elif isinstance(value, int):
            dictionary[key + "||INT"] = value.to_bytes(32, byteorder="big").hex()
        elif isinstance(value, dict):
            dictionary[key + "||DICT"] = encode_message(value).hex()
        else:
            raise ValueError(f"Unsupported type: {type(value)}")

    return json.dumps(dictionary).encode()


def decode_message(encoded: bytes) -> dict[
    str, str | SigningKey | VerifyingKey | EllipticCurvePrivateKey | EllipticCurvePublicKey | EllipticCurvePrivateKey | EllipticCurvePublicKey | bytes | dict | int]:
    decoded = json.loads(encoded.decode())
    decoded_message = {}
    for key, value in decoded.items():
        key, type_ = key.split("||")
        if type_ == "NONE":
            decoded_message[key] = None
        if type_ == "STR":
            decoded_message[key] = bytes.fromhex(value).decode()
        elif type_ == "SK":
            decoded_message[key] = SigningKey.from_pem(bytes.fromhex(value).decode())
        elif type_ == "VK":
            decoded_message[key] = VerifyingKey.from_pem(bytes.fromhex(value).decode())
        elif type_ == "BYTE":
            decoded_message[key] = bytes.fromhex(value)
        elif type_ == "INT":
            decoded_message[key] = int.from_bytes(bytes.fromhex(value), byteorder="big")
        elif type_ == "DICT":
            decoded_message[key] = decode_message(bytes.fromhex(value))
        elif type_ == "ECSK":
            decoded_message[key] = serialization.load_pem_private_key(
                bytes.fromhex(value),
                password=None,
                backend=default_backend()
            )
        elif type_ == "ECPK":
            decoded_message[key] = serialization.load_pem_public_key(
                bytes.fromhex(value),
                backend=default_backend()
            )
        else:
            raise ValueError(f"Unsupported type: {type_}")

    return decoded_message


def aes_gcm_encrypt(key, plaintext, associated_data):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return iv, ciphertext, encryptor.tag


def aes_gcm_decrypt(key, iv, ciphertext, associated_data, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

def sha256(content: bytes) -> bytes:
    return hashlib.sha256(content).digest()

def power(exponent: SigningKey, base: VerifyingKey, curve = ec.SECP256R1()):
    ecdh = ECDH(curve)
    ecdh.load_private_key(exponent)
    ecdh.load_received_public_key(base)
    return ecdh.generate_sharedsecret_bytes()