# otp.py - Task 5 (PRG based on AES in ECB mode)

from Crypto.Cipher import AES


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings of equal length.
    """
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        raise TypeError("xor_bytes expects bytes")

    if len(a) != len(b):
        raise ValueError("inputs must have equal length")

    return bytes(x ^ y for x, y in zip(a, b))


def normalize_seed(seed: bytes | int | str) -> bytes:
    """
    Normalize seed into a 16-byte AES key.
    """
    if isinstance(seed, int):
        return seed.to_bytes((seed.bit_length() + 7) // 8 or 1, "big").rjust(16, b"\x00")[:16]
    elif isinstance(seed, str):
        return seed.encode("utf-8").rjust(16, b"\x00")[:16]
    elif isinstance(seed, bytes):
        if len(seed) in (16, 24, 32):
            return seed
        return seed.rjust(16, b"\x00")[:16]
    else:
        raise TypeError("seed must be bytes, int, or str")


def generate_pad(seed: bytes | int | str, length: int, offset: int = 0) -> bytes:
    """
    Generate a pseudo-random byte pad of specified length starting at offset
    using a PRG built with AES in ECB mode (counter-mode expansion).
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if length == 0:
        return b""

    key = normalize_seed(seed)
    cipher = AES.new(key, AES.MODE_ECB)

    start_block = offset // 16
    end_block = (offset + length + 15) // 16
    start_offset = offset % 16

    blocks = [cipher.encrypt(c.to_bytes(16, "big")) for c in range(start_block, end_block)]
    stream = b"".join(blocks)
    return stream[start_offset : start_offset + length]


def encrypt(seed: bytes | int | str, plaintext: bytes, offset: int = 0) -> bytes:
    """
    Encrypt plaintext using an AES-ECB PRG generated pad.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("encrypt expects plaintext to be bytes")

    pad = generate_pad(seed, len(plaintext), offset=offset)
    return xor_bytes(plaintext, pad)


def decrypt(seed: bytes | int | str, ciphertext: bytes, offset: int = 0) -> bytes:
    """
    Decrypt ciphertext using an AES-ECB PRG generated pad.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("decrypt expects ciphertext to be bytes")

    pad = generate_pad(seed, len(ciphertext), offset=offset)
    return xor_bytes(ciphertext, pad)
