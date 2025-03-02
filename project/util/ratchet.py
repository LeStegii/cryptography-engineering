import os
from typing import Optional

from ecdsa import VerifyingKey, SigningKey

from project.util import crypto_utils
from project.util.crypto_utils import power_sk_vk, kdf_chain, generate_signature_key_pair


class DoubleRatchetState:
    def __init__(self, root_key: bytes, x: SigningKey, X: VerifyingKey, Y: Optional[VerifyingKey] = None, initialized_by_me: bool = True):
        self.x = x
        self.X = X
        self.Y = Y
        self.ck = root_key
        self.index = 0
        self.last_sender = "ME" if initialized_by_me else "THEM"

    def is_new_sequence(self) -> bool:
        return self.last_sender == "THEM"

    def encrypt(self, plaintext: bytes) -> dict[str, bytes | VerifyingKey | int]:
        DH = power_sk_vk(self.x, self.Y) if self.is_new_sequence() else b""
        mk, ck = kdf_chain(DH + self.ck)
        self.ck = ck

        iv, cipher, tag = crypto_utils.aes_gcm_encrypt(mk, plaintext, b"AD")
        message =  {
            "cipher": cipher,
            "iv": iv,
            "tag": tag,
            "index": self.index,
            "X": self.X
        }
        self.index += 1
        self.last_sender = "ME"
        return message

    def decrypt(self, message: dict[str, bytes | VerifyingKey | int]) -> bytes:
        self.index = message["index"]
        Y = message["X"]
        DH = power_sk_vk(self.x, Y) if self.is_new_sequence() else b""
        mk, ck = kdf_chain(DH + self.ck)
        self.ck = ck
        self.last_sender = "THEM"

        iv, cipher, tag = message["iv"], message["cipher"], message["tag"]
        return crypto_utils.aes_gcm_decrypt(mk, iv, cipher, b"AD", tag)

    def to_dict(self) -> dict[str, str | int | bool]:
        return {
            "x": self.x.to_string().hex(),
            "X": self.X.to_string().hex(),
            "Y": self.Y.to_string().hex(),
            "ck": self.ck.hex(),
            "index": self.index,
            "last_sender": self.last_sender
        }

    @staticmethod
    def from_dict(data: dict[str, str | int | bool]) -> "DoubleRatchetState":
        drs = DoubleRatchetState(
            root_key=bytes.fromhex(data["ck"]),
            x=SigningKey.from_string(bytes.fromhex(data["x"])),
            X=VerifyingKey.from_string(bytes.fromhex(data["X"])),
            Y=VerifyingKey.from_string(bytes.fromhex(data["Y"])),
            initialized_by_me=data["last_sender"] == "ME"
        )
        drs.index = data["index"]
        drs.new_sequence = data["new_sequence"]
        return drs



if __name__ == "__main__":
    x, X = generate_signature_key_pair()
    y, Y = generate_signature_key_pair()
    root_key = os.urandom(32)

    rs_A = DoubleRatchetState(root_key, x, X, Y, initialized_by_me=True)
    rs_B = DoubleRatchetState(root_key, y, Y, X, initialized_by_me=False)

    print("A", rs_A.to_dict())
    print("B", rs_B.to_dict())

    encrypted1 = rs_A.encrypt(b"Hey")
    encrypted2 = rs_A.encrypt(b"How are you?")

    print("A", rs_A.to_dict())
    print("B", rs_B.to_dict())

    decrypted1 = rs_B.decrypt(encrypted1)
    decrypted2 = rs_B.decrypt(encrypted2)
    print(decrypted1, decrypted2)

    print("A", rs_A.to_dict())
    print("B", rs_B.to_dict())


    encrypted3 = rs_B.encrypt(b"Good, you?")
    decrypted3 = rs_A.decrypt(encrypted3)
    print(decrypted3)

    print("A", rs_A.to_dict())
    print("B", rs_B.to_dict())
