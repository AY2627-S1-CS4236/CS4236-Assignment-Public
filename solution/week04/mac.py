"""Message authentication codes built from the course SPN cipher."""

from __future__ import annotations

from hmac import compare_digest

from .encoding import xor_bytes
from .modes import encrypt_cbc, pkcs7_pad
from .spn import BLOCK_SIZE, encrypt_block


ZERO_BLOCK = bytes(BLOCK_SIZE)
CMAC_KEY_SIZE = 2 * BLOCK_SIZE


def cmac(
    key: bytes,
    message: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    """Return the tag for the course's two-part-key CMAC construction."""

    if len(key) != CMAC_KEY_SIZE:
        raise ValueError("CMAC key must contain exactly 32 bytes")

    encryption_key = key[:BLOCK_SIZE]
    final_block_key = key[BLOCK_SIZE:]
    padded = pkcs7_pad(message)
    previous = ZERO_BLOCK

    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset : offset + BLOCK_SIZE]
        if offset == len(padded) - BLOCK_SIZE:
            block = xor_bytes(block, final_block_key)
        previous = encrypt_block(
            encryption_key,
            xor_bytes(block, previous),
            sbox=sbox,
            rounds=rounds,
        )

    return previous


def verify_cmac(
    key: bytes,
    message: bytes,
    tag: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bool:
    """Return whether ``tag`` is the course CMAC tag for ``message``."""

    if len(tag) != BLOCK_SIZE:
        return False
    expected = cmac(key, message, sbox=sbox, rounds=rounds)
    return compare_digest(expected, tag)


def pfmac(
    key: bytes,
    message: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    """Return a prefix-free CBC-MAC tag for ``message``."""

    if len(key) != BLOCK_SIZE:
        raise ValueError("PFMAC key must contain exactly 16 bytes")

    padded_block_count = len(pkcs7_pad(message)) // BLOCK_SIZE
    encoded_count = padded_block_count.to_bytes(BLOCK_SIZE, byteorder="big")
    ciphertext = encrypt_cbc(
        key,
        encoded_count + message,
        iv=ZERO_BLOCK,
        sbox=sbox,
        rounds=rounds,
    )
    return ciphertext[-BLOCK_SIZE:]


def verify_pfmac(
    key: bytes,
    message: bytes,
    tag: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bool:
    """Return whether ``tag`` is the PFMAC tag for ``message``."""

    if len(tag) != BLOCK_SIZE:
        return False
    expected = pfmac(key, message, sbox=sbox, rounds=rounds)
    return compare_digest(expected, tag)
