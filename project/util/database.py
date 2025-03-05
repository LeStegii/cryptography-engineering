import csv
import json
import os
from pathlib import Path
from typing import Any, Optional

from project.util import crypto_utils
from project.util.serializer import serializer


def load_or_create_key(key_path: str):
    path = Path(key_path)
    if path.exists():
        with open(key_path, "rb") as key_file:
            key = bytes.fromhex(key_file.read().decode())
    else:
        key = os.urandom(32)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(key_path, "wb") as key_file:
            key_file.write(key.hex().encode())
    return key


def decrypt_database(cipher: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    return crypto_utils.aes_gcm_decrypt(key, iv, cipher, b"DB", tag)


def encrypt_database(content: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    iv, encrypted_password, tag = crypto_utils.aes_gcm_encrypt(key, content, b"DB")
    return iv, encrypted_password, tag


def encode_database(data: dict[str, Any]) -> dict[str, str]:
    encoded = {}
    for key, value in data.items():
        if isinstance(value, dict):
            encoded[key] = encode_database(value)
        elif isinstance(value, list):
            encoded[key] = [encode_database(item) if type(item) == dict else serializer.encode_value(item) for item in value]
        else:
            encoded[key] = serializer.encode_value(value)
    return encoded


def decode_database(encoded: dict[str, str]) -> dict[str, Any]:
    decoded = {}
    for key, value in encoded.items():
        if isinstance(value, dict):
            decoded[key] = decode_database(value)
        elif isinstance(value, list):
            decoded[key] = [decode_database(item) if type(item) == dict else serializer.decode_value(item) for item in value]
        else:
            decoded[key] = serializer.decode_value(value)
    return decoded


class Database:
    def __init__(self, path: str, key_path: Optional[str] = None, cipher: bool = False):
        if cipher and not key_path:
            raise ValueError("Key path must be provided when cipher is enabled")
        self.cipher = cipher
        self.key: bytes = load_or_create_key(key_path) if cipher else b""
        self.path: str = path
        self.data = self.load(path)

    def load(self, path: str):

        if not Path(path).exists():
            return {}

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "r") as file:
            if self.cipher:
                reader = csv.reader(file)
                cipher: list[str] = reader.__next__()
                iv: bytes = bytes.fromhex(cipher[0])
                cipher_text: bytes = bytes.fromhex(cipher[1])
                tag: bytes = bytes.fromhex(cipher[2])

                decrypted = decrypt_database(cipher_text, self.key, iv, tag)
                return serializer.decode_message(decrypted)
            else:
                return decode_database(json.loads(file.read()))

    def insert(self, key: str | bytes, value: Any, save: bool = True):
        if not isinstance(key, (str, bytes)):
            raise TypeError("Key must be a string or bytes")

        self.data[key if isinstance(key, str) else key.decode()] = value

        if save:
            self.save()

    def get(self, key: str | bytes) -> Any:
        if not isinstance(key, (str, bytes)):
            raise TypeError("Key must be a string or bytes")
        return self.data.get(key if isinstance(key, str) else key.decode())

    def update(self, key: str | bytes, value: Any, save: bool = True):
        if not isinstance(key, (str, bytes)):
            raise TypeError("Key must be a string or bytes")

        if isinstance(value, dict) and key in self.data:
            self.data[key if isinstance(key, str) else key.decode()].update(value)
        else:
            self.data[key if isinstance(key, str) else key.decode()] = value
        if save:
            self.save()

    def delete(self, key: str | bytes, save: bool = True):
        if not isinstance(key, (str, bytes)):
            raise TypeError("Key must be a string or bytes")
        self.data.pop(key if isinstance(key, str) else key.decode())

    def save(self):

        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as file:
            if self.cipher:
                writer = csv.writer(file)
                encoded = serializer.encode_message(self.data)
                iv, cipher, tag = encrypt_database(encoded, self.key)
                writer.writerow([iv.hex(), cipher.hex(), tag.hex()])
            else:
                file.write(json.dumps(encode_database(self.data), indent=4))

    def has(self, key: str | bytes) -> bool:
        if not isinstance(key, (str, bytes)):
            raise TypeError("Key must be a string or bytes")
        return (key if isinstance(key, str) else key.decode()) in self.data

    def keys(self):
        return self.data.keys()

    def clear(self, save: bool = True):
        self.data.clear()
        if save:
            self.save()
