import hmac
import os
from hashlib import sha256
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ecdsa import SigningKey, VerifyingKey, ECDH, util
from ecdsa.curves import NIST256p as CURVE


def generate_one_time_pre_keys(amount: int):
    one_time_prekeys = []
    for i in range(amount):
        ok, OPK = generate_signature_key_pair()
        one_time_prekeys.append((ok, OPK))
    return one_time_prekeys


def generate_signature_key_pair() -> Tuple[SigningKey, VerifyingKey]:
    sk = SigningKey.generate(CURVE)
    vk = sk.get_verifying_key()
    return sk, vk


def power_sk_vk(power: SigningKey, base: VerifyingKey):
    """
    Calculates base^power
    :param power: The private key to raise the base to
    :param base: The public key to raise to the power
    :return: The shared secret (base^power)
    """
    ecdh = ECDH(CURVE)
    ecdh.load_private_key(power)
    ecdh.load_received_public_key(base)
    return ecdh.generate_sharedsecret_bytes()


def ecdsa_sign(message: bytes, private_key: SigningKey, nonce=None):
    signature = None
    if nonce:  # If the nonce is explicitly specified
        signature = private_key.sign(
            message,
            k=nonce,
            hashfunc=sha256,
            sigencode=util.sigencode_der
        )
    else:
        signature = private_key.sign(
            message,
            hashfunc=sha256,
            sigencode=util.sigencode_der
        )
    return signature


def ecdsa_verify(signature: bytes, message: bytes, public_key: VerifyingKey):
    try:
        is_valid = public_key.verify(
            signature,
            message,
            hashfunc=sha256,
            sigdecode=util.sigdecode_der
        )
        return is_valid
    except:
        return False


def kdf_chain(ck: bytes) -> Tuple[bytes, bytes]:
    derived = hkdf_extract(b'', ck, length=64)
    return derived[:32], derived[32:]


def hkdf_extract(salt: bytes, input_key_material: bytes, length=32):
    hkdf_extract = HKDF(
        algorithm=SHA256(),
        length=length,
        salt=salt,
        info=None,
        backend=default_backend()
    )
    prk = hkdf_extract.derive(input_key_material)
    return prk


def hkdf_expand(prk: bytes, info: bytes, length=32):
    hkdf_expand = HKDF(
        algorithm=SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    )
    derived_key = hkdf_expand.derive(prk)
    return derived_key

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> Tuple[bytes, bytes, bytes]:
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return iv, ciphertext, encryptor.tag


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, associated_data: bytes, tag: bytes) -> bytes:
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


def salt_password(password: str, salt: bytes, pepper: bytes) -> bytes:
    return HMAC(salt, password.encode() + pepper)

def HMAC(key: bytes, content: bytes) -> bytes:
    return hmac.new(key, content, sha256).digest()

def KDF(DH: bytes, ck: bytes) -> tuple[bytes, bytes]:
    key = hkdf_extract(salt=DH, input_key_material=ck, length=64)
    ck = key[:32]
    mk = key[32:]
    return ck, mk