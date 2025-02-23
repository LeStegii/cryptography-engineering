import csv
import os
from pathlib import Path
from typing import Any

import utils


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


def decode_database(cipher: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    return utils.aes_gcm_decrypt(key, iv, cipher, b"DB", tag)


def encode_database(content: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    iv, encrypted_password, tag = utils.aes_gcm_encrypt(key, content, b"DB")
    return iv, encrypted_password, tag


class Database:
    def __init__(self, path: str, key_path: str):
        self.key: bytes = load_or_create_key(key_path)
        self.path: str = path
        self.data = self.load(path)

    def load(self, path: str):

        if not Path(path).exists():
            return {}

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "r") as file:
            reader = csv.reader(file)
            cipher: list[str] = reader.__next__()
            iv: bytes = bytes.fromhex(cipher[0])
            cipher_text: bytes = bytes.fromhex(cipher[1])
            tag: bytes = bytes.fromhex(cipher[2])

            decrypted = decode_database(cipher_text, self.key, iv, tag)
            return utils.decode_message(decrypted)

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
        del self.data[key if isinstance(key, str) else key.decode()]

    def save(self):

        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as file:
            writer = csv.writer(file)
            encoded = utils.encode_message(self.data)
            iv, cipher, tag = encode_database(encoded, self.key)
            writer.writerow([iv.hex(), cipher.hex(), tag.hex()])

    def has(self, key: str | bytes) -> bool:
        if not isinstance(key, (str, bytes)):
            raise TypeError("Key must be a string or bytes")
        return (key if isinstance(key, str) else key.decode()) in self.data

    def keys(self):
        return self.data.keys()