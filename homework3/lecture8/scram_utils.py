import hashlib
import hmac


def H(n: int, pw: str | bytes, r: bytes) -> bytes:
    return iterate_hash_with_salt(password=pw, salt=r, num_of_iterations=n)


def iterate_hash_with_salt(password: str | bytes, salt: bytes, num_of_iterations: int) -> bytes:
    pw = password.encode() if isinstance(password, str) else password
    padded_salt = salt + b"\x00\x00\x00\x01"

    hash_1 = HMAC(pw, padded_salt)
    hashes = [hash_1]

    for _ in range(1, num_of_iterations):
        hash_i = HMAC(pw, hashes[-1])
        hashes.append(hash_i)

    password_file = b"\x00" * len(hashes[0])
    for h in hashes:
        password_file = xor_bytes(password_file, h)

    return password_file


def HMAC(key: bytes, content: bytes) -> bytes:
    return hmac.new(key, content, hashlib.sha256).digest()

def sha256(content: bytes) -> bytes:
    return hashlib.sha256(content).digest()

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return bytes([a ^ b for a, b in zip(b1, b2)])
