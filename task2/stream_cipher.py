# otp.py

import random


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings of equal length.
    """
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        raise TypeError("xor_bytes expects bytes")

    if len(a) != len(b):
        raise ValueError("inputs must have equal length")

    return bytes(x ^ y for x, y in zip(a, b))


def generate_pad(seed: int | bytes | str, length: int, offset: int = 0) -> bytes:
    """
    Generate a pseudo-random byte pad of specified length starting at offset
    using Python's random module initialized with seed.
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    if offset < 0:
        raise ValueError("offset must be non-negative")

    rng = random.Random(seed)
    for _ in range(offset):
        rng.getrandbits(8)
    return bytes(rng.getrandbits(8) for _ in range(length))


def encrypt(seed: int | bytes | str, plaintext: bytes, offset: int = 0) -> bytes:
    """
    Encrypt plaintext using a pseudo-random pad generated from a seed.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("encrypt expects plaintext to be bytes")

    pad = generate_pad(seed, len(plaintext), offset=offset)
    return xor_bytes(plaintext, pad)


def decrypt(seed: int | bytes | str, ciphertext: bytes, offset: int = 0) -> bytes:
    """
    Decrypt ciphertext using a pseudo-random pad generated from a seed.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("decrypt expects ciphertext to be bytes")

    pad = generate_pad(seed, len(ciphertext), offset=offset)
    return xor_bytes(ciphertext, pad)