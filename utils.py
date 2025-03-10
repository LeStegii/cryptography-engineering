import hashlib
import hmac
import json
import os
import zlib
from hashlib import sha256 as HASH_FUNC
from typing import Tuple, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ecdsa import util, VerifyingKey, SigningKey, ECDH
from ecdsa.curves import NIST256p as CURVE
from ecdsa.ellipticcurve import Point

from project.util.message import Message


def generate_signature_key_pair() -> Tuple[SigningKey, VerifyingKey]:
    sk = SigningKey.generate(CURVE)
    vk = sk.get_verifying_key()
    return sk, vk


def power_sk_vk(power: SigningKey, base: VerifyingKey):
    ecdh = ECDH(CURVE)
    ecdh.load_private_key(power)
    ecdh.load_received_public_key(base)
    return ecdh.generate_sharedsecret_bytes()


def generate_ecdh_key_pair(group):
    private_key = ec.generate_private_key(group)
    public_key = private_key.public_key()
    return private_key, public_key


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


def compress(value: bytes) -> bytes:
    """Compress a string using a compression algorithm."""
    return zlib.compress(value)

def decompress(value: bytes) -> bytes:
    """Decompress a compressed string."""
    return zlib.decompress(value)

def encode_list(value: list) -> str:
    string = ""
    for item in value:
        item_type = type(item)
        prefix, encode, _ = TYPE_MAP.get(item_type, ("U", lambda x: json.dumps(x), lambda x: json.loads(x)))
        encoded = encode(item)
        string += f"{prefix}:{encoded};"
    return string

def decode_list(encoded: str) -> list:
    decoded = []
    for item in encoded.split(";"):
        if not item:
            continue
        prefix, value = item.split(":", 1)
        value_type = type_for_prefix(prefix)
        _, _, decode = TYPE_MAP.get(value_type, ("U", lambda x: json.dumps(x), lambda x: json.loads(x)))
        decoded.append(decode(value))
    return decoded

TYPE_MAP = {
    None: ("N", lambda value: "", lambda encoded: None),
    str: ("S", lambda value: value, lambda encoded: encoded),
    bool: ("B", lambda value: str(int(value)), lambda encoded: bool(int(encoded))),
    int: ("I", lambda value: str(value), lambda encoded: int(encoded)),
    bytes: ("Y", lambda value: value.hex(), lambda encoded: bytes.fromhex(encoded)),
    SigningKey: (
    "SK", lambda value: value.to_pem().hex(), lambda encoded: SigningKey.from_pem(bytes.fromhex(encoded).decode())),
    VerifyingKey: (
    "VK", lambda value: value.to_pem().hex(), lambda encoded: VerifyingKey.from_pem(bytes.fromhex(encoded).decode())),
    EllipticCurvePrivateKey: (
        "ECSK",
        lambda value: value.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex(),
        lambda encoded: serialization.load_der_private_key(bytes.fromhex(encoded), password=None)
    ),
    EllipticCurvePublicKey: (
        "ECPK",
        lambda value: value.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex(),
        lambda encoded: serialization.load_der_public_key(bytes.fromhex(encoded))
    ),
    Point: ("P", lambda value: value.to_bytes().hex(), lambda encoded: Point.from_bytes(bytes.fromhex(encoded), CURVE)),
    Message: ("M", lambda value: value.to_bytes().hex(), lambda encoded: Message.from_bytes(bytes.fromhex(encoded))),
    dict: ("D", lambda value: encode_message(value).hex(), lambda encoded: decode_message(bytes.fromhex(encoded))),
    list: ("L", encode_list, decode_list)
}


def encode_message(message: dict[str, Any]) -> bytes:
    return compress(json.dumps(encode_dict(message)).encode())

def encode_value(value: Any) -> str:
    value_type = type(value)
    prefix, encode, _ = TYPE_MAP.get(value_type, ("U", lambda x: json.dumps(x), lambda x: json.loads(x)))

    return f"{prefix}:{encode(value)}"

def encode_dict(message: dict[str, Any]) -> dict[str, str]:
    encoded = {}
    for key, value in message.items():
        encoded[key] = encode_value(value)

    return encoded

def decode_message(encoded: bytes) -> dict[str, Any]:
    return decode_dict(json.loads(decompress(encoded).decode()))


def decode_value(encoded: str) -> Any:
    prefix, value = encoded.split(":", 1)
    value_type = type_for_prefix(prefix)
    _, _, decode = TYPE_MAP.get(value_type, ("U", lambda x: json.dumps(x), lambda x: json.loads(x)))

    return decode(value)

def decode_dict(encoded: dict[str, str]) -> dict[str, Any]:
    decoded = {}
    for key, prefixed_value in encoded.items():
        decoded[key] = decode_value(prefixed_value)

    return decoded

def type_for_prefix(prefix):
    try:
        return [t for t, (p, _, _) in TYPE_MAP.items() if p == prefix][0]
    except IndexError:
        print(f"Unknown type prefix: {prefix}")

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


def power(exponent: SigningKey, base: VerifyingKey, curve=ec.SECP256R1()):
    ecdh = ECDH(curve)
    ecdh.load_private_key(exponent)
    ecdh.load_received_public_key(base)
    return ecdh.generate_sharedsecret_bytes()


def HMAC(key: bytes, content: bytes) -> bytes:
    return hmac.new(key, content, hashlib.sha256).digest()


def salt_password(password: str | bytes, salt: bytes) -> bytes:
    return HMAC(salt, password.encode() if isinstance(password, str) else password)

# HKDF.Extract
def hkdf_extract(salt, input_key_material, length=32):
    # Extract: Derive the PRK (pseudorandom key)
    hkdf_extract = HKDF(
        algorithm=SHA256(),
        length=length,             # Length of the PRK (match SHA-256 output: 32 bytes)
        salt=salt,             # Salt can be any value or None
        info=None,             # No info for Extract phase
        backend=default_backend()
    )
    prk = hkdf_extract.derive(input_key_material)
    return prk

# HKDF.Expand
def hkdf_expand(prk, info, length=32):
    # Expand: Derive the final key from the PRK
    hkdf_expand = HKDF(
        algorithm=SHA256(),
        length=length,         # Desired output length of the final derived key
        salt=None,             # No salt in the Expand phase (PRK is used directly as key)
        info=info,             # Context-specific info parameter
        backend=default_backend()
    )
    derived_key = hkdf_expand.derive(prk)
    return derived_key


if __name__ == "__main__":
    private_key, public_key = generate_signature_key_pair()
    encoded = encode_message({"key": private_key, "key2": public_key})
    print(len(encoded))
    compressed = compress(encoded)
    print(len(compressed))
    uncompressed = decompress(compressed)
    print(len(uncompressed))

    print(encoded == uncompressed)