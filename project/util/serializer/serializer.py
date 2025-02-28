import json
import zlib
from typing import Any

from project.util.serializer.serializer_type_map import type_for_prefix, TYPE_MAP


def compress(value: bytes) -> bytes:
    """Compress a string using a compression algorithm."""
    return zlib.compress(value)


def decompress(value: bytes) -> bytes:
    """Decompress a compressed string."""
    return zlib.decompress(value)


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


