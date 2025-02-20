import hashlib
import hmac
import json
import os
from hashlib import sha256 as HASH_FUNC
from typing import Tuple, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ecdsa import util, VerifyingKey, SigningKey, ECDH
from ecdsa.curves import NIST256p as CURVE
from ecdsa.ellipticcurve import Point

from project.message import Message


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


# Short type prefixes for efficiency
TYPE_MAP = {
    None: ("N", lambda value: "", lambda encoded: None),
    str: ("S", lambda value: value, lambda encoded: encoded),
    bool: ("B", lambda value: int(value), lambda encoded: bool(int(encoded))),
    int: ("I", lambda value: value, lambda encoded: int(encoded)),
    bytes: ("Y", lambda value: value.hex(), lambda encoded: bytes.fromhex(encoded)),
    SigningKey: (
    "SK", lambda value: value.to_pem().hex(), lambda encoded: SigningKey.from_pem(bytes.fromhex(encoded).decode())),
    VerifyingKey: (
    "VK", lambda value: value.to_pem().hex(), lambda encoded: VerifyingKey.from_pem(bytes.fromhex(encoded).decode())),
    EllipticCurvePrivateKey: (
        "ECSK",
        lambda value: value.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).hex(),
        lambda encoded: serialization.load_pem_private_key(bytes.fromhex(encoded), password=None)
    ),
    EllipticCurvePublicKey: (
        "ECPK",
        lambda value: value.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex(),
        lambda encoded: serialization.load_pem_public_key(bytes.fromhex(encoded))
    ),
    Point: ("P", lambda value: value.to_bytes().hex(), lambda encoded: Point.from_bytes(bytes.fromhex(encoded), CURVE)),
    Message: ("M", lambda value: value.to_bytes().hex(), lambda encoded: Message.from_bytes(bytes.fromhex(encoded))),
    dict: ("D", lambda value: encode_message(value).hex(), lambda encoded: decode_message(bytes.fromhex(encoded))),
    list[str]: ("LS", lambda value: ";".join(value), lambda encoded: encoded.split(";")),
    list: ("L", lambda value: ";".join(TYPE_MAP.get(type(item))[1](item) for item in value),
           lambda encoded: [TYPE_MAP.get(type(item))[2](item) for item in encoded.split(";")])
}


def encode_message(message: dict[str, Any]) -> bytes:
    encoded = {}
    for key, value in message.items():
        value_type = type(value)
        prefix, encode, _ = TYPE_MAP.get(value_type, ("U", lambda x: json.dumps(x), lambda x: json.loads(x)))

        encoded[key] = f"{prefix}:{encode(value)}"

    return json.dumps(encoded).encode()


def decode_message(encoded: bytes) -> dict[str, Any]:
    decoded = json.loads(encoded.decode())
    message = {}

    for key, prefixed_value in decoded.items():
        prefix, value = prefixed_value.split(":", 1)
        value_type = [t for t, (p, _, _) in TYPE_MAP.items() if p == prefix][0]
        _, _, decode = TYPE_MAP.get(value_type, ("U", lambda x: json.dumps(x), lambda x: json.loads(x)))

        message[key] = decode(value)

    return message


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
