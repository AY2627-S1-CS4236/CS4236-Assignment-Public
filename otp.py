# otp.py

from pathlib import Path


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings of equal length.
    """
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        raise TypeError("xor_bytes expects bytes")

    if len(a) != len(b):
        raise ValueError("inputs must have equal length")

    return bytes(x ^ y for x, y in zip(a, b))


def xor_bytes_cyclic(data: bytes, pad: bytes, offset: int = 0) -> bytes:
    """
    XOR data with key pad. If data length (or offset + length) exceeds pad length,
    wrap around to restart from the beginning of the pad.
    """
    if not isinstance(data, bytes) or not isinstance(pad, bytes):
        raise TypeError("xor_bytes_cyclic expects bytes")

    if len(pad) == 0:
        raise ValueError("OTP pad must not be empty")

    pad_len = len(pad)
    return bytes(b ^ pad[(offset + i) % pad_len] for i, b in enumerate(data))


def encrypt(pad: bytes, plaintext: bytes, offset: int = 0) -> bytes:
    """
    Encrypt plaintext using a key pad.

    If the pad is shorter than the plaintext (or offset exceeds pad length),
    it restarts/wraps from the beginning of the pad.
    """
    if not isinstance(pad, bytes) or not isinstance(plaintext, bytes):
        raise TypeError("encrypt expects bytes")

    return xor_bytes_cyclic(plaintext, pad, offset=offset)


def decrypt(pad: bytes, ciphertext: bytes, offset: int = 0) -> bytes:
    """
    Decrypt ciphertext using a key pad.

    OTP decryption is the same operation as encryption.
    If the pad is shorter than the ciphertext (or offset exceeds pad length),
    it restarts/wraps from the beginning of the pad.
    """
    if not isinstance(pad, bytes) or not isinstance(ciphertext, bytes):
        raise TypeError("decrypt expects bytes")

    return xor_bytes_cyclic(ciphertext, pad, offset=offset)


def load_key_file(key_file: str | Path) -> bytes:
    """
    Load OTP key material from a file.
    """
    path = Path(key_file)

    if not path.exists():
        raise FileNotFoundError(f"key file does not exist: {path}")

    key = path.read_bytes()

    if len(key) < 2:
        raise ValueError("key file must contain at least 2 bytes")

    return key


def split_key(key: bytes) -> tuple[bytes, bytes]:
    """
    Split key material into two independent pads.

    First half:  client -> server
    Second half: server -> client
    """
    if len(key) < 2:
        raise ValueError("key must contain at least 2 bytes")

    midpoint = len(key) // 2

    client_to_server_pad = key[:midpoint]
    server_to_client_pad = key[midpoint:]

    return client_to_server_pad, server_to_client_pad