import os
from typing import Optional

from ecdsa import VerifyingKey, SigningKey

from project.util import crypto_utils
from project.util.crypto_utils import power_sk_vk, kdf_chain, generate_signature_key_pair
from project.util.utils import debug


class DoubleRatchetState:
    def __init__(self, root_key: bytes, x: Optional[SigningKey], X: Optional[VerifyingKey], Y: Optional[VerifyingKey] = None, initialized_by_me: bool = True):
        """
        To initialize the DRS as a first time sender, set Y to the recipient's public key and leave x and X as None.
        To initialize the DRS as a first time receiver, set x and X to your own key pair and leave Y as None, and set initialized_by_me to False.
        :param root_key: The root key to derive the chain key from
        :param x: Your own private key
        :param X: Your own public key
        :param Y: The other person's public key
        :param initialized_by_me: Whether you are the one initializing the conversation
        """
        self.x = x
        self.X = X
        self.Y = Y
        self.ck = root_key
        self.index = 0
        self.last_sender = "ME" if initialized_by_me else "THEM"


    def compute_dh(self, Y: VerifyingKey):
        DH = power_sk_vk(self.x, Y)
        self.Y = Y
        return DH

    def encrypt(self, plaintext: bytes) -> dict[str, bytes | VerifyingKey | int]:
        if self.index == 0 or self.last_sender == "THEM":
            self.x, self.X = generate_signature_key_pair()
            DH = self.compute_dh(self.Y)
        else:
            DH = b""

        mk, ck = kdf_chain(DH + self.ck)
        self.ck = ck

        # Encrypt message
        iv, cipher, tag = crypto_utils.aes_gcm_encrypt(mk, plaintext, b"AD")
        message = {
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
        self.Y = message["X"]

        if self.index == 0 or self.last_sender == "ME":
            DH = self.compute_dh(self.Y)
        else:
            DH = b""

        mk, ck = kdf_chain(DH + self.ck)
        self.ck = ck
        self.last_sender = "THEM"

        iv, cipher, tag = message["iv"], message["cipher"], message["tag"]
        try:
            return crypto_utils.aes_gcm_decrypt(mk, iv, cipher, b"AD", tag)
        except Exception as e:
            debug(f"Failed to decrypt message: {e}")
            return b""

    def to_dict(self) -> dict[str, str | int | bool]:
        return {
            "x": self.x.to_pem().hex() if self.x else None,
            "X": self.X.to_pem().hex() if self.X else None,
            "Y": self.Y.to_pem().hex() if self.Y else None,
            "ck": self.ck.hex(),
            "index": self.index,
            "last_sender": self.last_sender
        }

    @staticmethod
    def from_dict(data: dict[str, str | int | bool]) -> "DoubleRatchetState":
        drs = DoubleRatchetState(
            root_key=bytes.fromhex(data["ck"]),
            x=SigningKey.from_pem(bytes.fromhex(data["x"]).decode()) if data["x"] else None,
            X=VerifyingKey.from_pem(bytes.fromhex(data["X"]).decode()) if data["X"] else None,
            Y=VerifyingKey.from_pem(bytes.fromhex(data["Y"]).decode()) if data["Y"] else None,
            initialized_by_me=data["last_sender"] == "ME"
        )
        drs.index = data["index"]
        return drs


if __name__ == "__main__":
    x, X = generate_signature_key_pair()
    y, Y = generate_signature_key_pair()
    root_key = os.urandom(32)

    rs_A = DoubleRatchetState(root_key, None, None, Y, initialized_by_me=True)
    rs_B = DoubleRatchetState(root_key, y, Y, None, initialized_by_me=False)

    encrypted1 = rs_A.encrypt(b"Hey")
    encrypted2 = rs_A.encrypt(b"How are you?")

    print(rs_B.decrypt(encrypted1))
    print(rs_B.decrypt(encrypted2))

    encrypted3 = rs_B.encrypt(b"Good, thanks!")
    encrypted4 = rs_B.encrypt(b"Want to meet up?")

    print(rs_A.decrypt(encrypted3))
    print(rs_A.decrypt(encrypted4))

    encrypted5 = rs_A.encrypt(b"Sure, when?")

    print(rs_B.decrypt(encrypted5))

    encrypted6 = rs_B.encrypt(b"Tomorrow?")
    encrypted7 = rs_B.encrypt(b"Maybe 18:00?")
    encrypted8 = rs_B.encrypt(b"Where?")

    print(rs_A.decrypt(encrypted6))
    print(rs_A.decrypt(encrypted7))
    print(rs_A.decrypt(encrypted8))

    encrypted9 = rs_A.encrypt(b"At the park")

    print(rs_B.decrypt(encrypted9))

