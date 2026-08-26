"""Recover the SeedSafe Week 02 startup secret."""

from __future__ import annotations

import json
from urllib.request import urlopen

from educrypto.spn import decrypt_block, encrypt_block


BLOCK_SIZE = 16
ROUNDS = 10
SBOX = bytes(
    ((((value >> 4) ^ (value & 0x0F)) << 4) | (value & 0x0F))
    for value in range(256)
)
ZERO_KEY = bytes(BLOCK_SIZE)


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(left_byte ^ right_byte for left_byte, right_byte in zip(left, right))


def _get_json(base_url: str, path: str) -> dict[str, object]:
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    with urlopen(url, timeout=5) as response:
        return json.load(response)


def _remove_mask(ciphertext: bytes, mask: bytes) -> bytes:
    """Invert the common affine transformation for every archived block."""

    return b"".join(
        decrypt_block(
            ZERO_KEY,
            _xor(ciphertext[offset : offset + BLOCK_SIZE], mask),
            sbox=SBOX,
            rounds=ROUNDS,
        )
        for offset in range(0, len(ciphertext), BLOCK_SIZE)
    )


def solve(base_url: str) -> str:
    """Recover and return the exact secret encrypted when SeedSafe started."""

    payload = _get_json(base_url, "/api/v1/backups")
    records = payload.get("backups")
    record = records[-1]
    created_at = record.get("created_at")
    ciphertext_hex = record.get("ciphertext_hex")
    ciphertext = bytes.fromhex(ciphertext_hex)
    stamp = f"\n\nSeedSafe {created_at}".encode("utf-8")

    # The deployed substitution and permutation are linear over bits. For one
    # fixed recovery key, each block therefore has the form:
    #
    #     ciphertext = linear(plaintext) XOR mask
    #
    # The timestamp makes the final plaintext block known once its zero-fill
    # length is guessed. Encryption under the all-zero key computes only the
    # linear part because its complete expanded schedule also remains zero.
    for padding_length in range(BLOCK_SIZE):
        known_block = (stamp + b"\x00" * padding_length)[-BLOCK_SIZE:]
        linear_image = encrypt_block(
            ZERO_KEY,
            known_block,
            sbox=SBOX,
            rounds=ROUNDS,
        )
        mask = _xor(ciphertext[-BLOCK_SIZE:], linear_image)
        padded_plaintext = _remove_mask(ciphertext, mask)
        plaintext = padded_plaintext.rstrip(b"\x00")

        if not plaintext.endswith(stamp):
            continue

        secret = plaintext[: -len(stamp)]
        try:
            return secret.decode("utf-8")
        except UnicodeDecodeError:
            continue

    raise ValueError("the startup secret could not be recovered")
