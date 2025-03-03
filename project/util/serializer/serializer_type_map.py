import json
from types import NoneType

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from ecdsa import VerifyingKey, SigningKey
from ecdsa.curves import NIST256p as CURVE
from ecdsa.ellipticcurve import Point

from project.util.message import Message
from project.util.ratchet import DoubleRatchetState


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


def encode_dict(message: dict[str, any]) -> str:
    string = ""
    for key, value in message.items():
        value_type = type(value)
        prefix, encode, _ = TYPE_MAP.get(value_type, ("U", lambda x: json.dumps(x), lambda x: json.loads(x)))
        encoded = encode(value)
        string += f"{key}:{prefix}:{encoded}|"
    return string


def decode_dict(encoded: str) -> dict[str, any]:
    decoded = {}
    for item in encoded.split("|"):
        if not item:
            continue
        key, item = item.split(":", 1)
        prefix, value = item.split(":", 1)
        value_type = type_for_prefix(prefix)
        _, _, decode = TYPE_MAP.get(value_type, ("U", lambda x: json.dumps(x), lambda x: json.loads(x)))
        decoded[key] = decode(value)
    return decoded


def type_for_prefix(prefix):
    try:
        return [t for t, (p, _, _) in TYPE_MAP.items() if p == prefix][0]
    except IndexError:
        print(f"Unknown type prefix: {prefix}")


TYPE_MAP = {
    NoneType: ("N", lambda value: "", lambda encoded: None),
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
    DoubleRatchetState: ("DRS", lambda value: encode_dict(value.to_dict()), lambda encoded: DoubleRatchetState.from_dict(decode_dict(encoded))),
    dict: ("D", encode_dict, decode_dict),
    list: ("L", encode_list, decode_list)
}
