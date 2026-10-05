"""Davies–Meyer, strengthened Merkle–Damgård, and a configurable sponge."""

from __future__ import annotations

from .encoding import xor_bytes
from .spn import BLOCK_SIZE, encrypt_block


AES_SBOX: bytes = bytes.fromhex(
    """
    63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
    ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
    b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
    04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
    09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
    53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
    d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
    51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
    cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
    60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
    e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
    e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
    ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
    70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
    e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
    8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
    """
)
MD_IV: bytes = b"\xff" * BLOCK_SIZE
SPONGE_KEY: bytes = bytes(range(BLOCK_SIZE))


def davies_meyer(
    data: bytes,
    *,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes:
    """Compress H || M to Enc(key=M, plaintext=H) XOR H."""

    state, message_block = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    encrypted = encrypt_block(message_block, state, sbox=sbox, rounds=rounds)
    return xor_bytes(encrypted, state)


def merkle_damgard_pad(message: bytes) -> bytes:
    """Append 10*, then the original bit length in a full 16-byte block."""

    bit_length = (8 * len(message)).to_bytes(BLOCK_SIZE, "big")
    zero_count = (-len(message) - 1) % BLOCK_SIZE
    return message + b"\x80" + bytes(zero_count) + bit_length


def merkle_damgard(
    message: bytes,
    *,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes:
    """Hash an arbitrary-length message using the fixed all-FF IV."""

    padded = merkle_damgard_pad(message)
    state = MD_IV
    for offset in range(0, len(padded), BLOCK_SIZE):
        state = davies_meyer(
            state + padded[offset : offset + BLOCK_SIZE],
            sbox=sbox,
            rounds=rounds,
        )
    return state


def sponge_pad(message: bytes, *, c: int) -> bytes:
    """Append MSB-first pad10*1 for the rate implied by capacity c."""

    if not 0 <= c < BLOCK_SIZE:
        raise ValueError("capacity must be between 0 and 15 bytes")
    rate = BLOCK_SIZE - c
    padding_length = rate - len(message) % rate
    if padding_length == 1:
        return message + b"\x81"
    return message + b"\x80" + bytes(padding_length - 2) + b"\x01"


def sponge_hash(
    message: bytes,
    *,
    c: int,
    digest_length: int,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes:
    """Return a variable-length digest from a fixed-key, zero-state sponge."""

    if digest_length < 0:
        raise ValueError("digest length must be non-negative")
    padded = sponge_pad(message, c=c)
    if digest_length == 0:
        return b""

    rate = BLOCK_SIZE - c
    state = bytes(BLOCK_SIZE)
    for offset in range(0, len(padded), rate):
        state = encrypt_block(
            SPONGE_KEY,
            xor_bytes(state[:rate], padded[offset : offset + rate]) + state[rate:],
            sbox=sbox,
            rounds=rounds,
        )

    output = bytearray()
    while len(output) < digest_length:
        output.extend(state[: min(rate, digest_length - len(output))])
        if len(output) < digest_length:
            state = encrypt_block(SPONGE_KEY, state, sbox=sbox, rounds=rounds)
    return bytes(output)
