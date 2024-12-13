# Generate ECDH private and public key pair
import os
# Use SHA256 as the hash function used in DSA
from hashlib import sha256 as HASH_FUNC

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ecdsa import util  # pip install ecdsa


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
