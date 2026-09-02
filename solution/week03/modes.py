"""Block-cipher modes built from the Week 02 SPN primitive."""

from __future__ import annotations

from .encoding import xor_bytes
from .spn import BLOCK_SIZE, decrypt_block, encrypt_block


CTR_IV_SIZE = BLOCK_SIZE // 2
CTR_COUNTER_SIZE = BLOCK_SIZE - CTR_IV_SIZE


def pkcs7_pad(data: bytes) -> bytes:
    """Pad data to a multiple of the 16-byte SPN block size."""

    padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(padded_data: bytes) -> bytes:
    """Remove PKCS#7 padding from valid padded data."""

    padding_length = padded_data[-1]
    return padded_data[:-padding_length]


def encrypt_ecb(
    key: bytes,
    plaintext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    """Encrypt PKCS#7-padded blocks independently using the SPN cipher."""

    padded = pkcs7_pad(plaintext)
    return b"".join(
        encrypt_block(
            key,
            padded[offset : offset + BLOCK_SIZE],
            sbox=sbox,
            rounds=rounds,
        )
        for offset in range(0, len(padded), BLOCK_SIZE)
    )


def decrypt_ecb(
    key: bytes,
    ciphertext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    """Decrypt ECB blocks and remove PKCS#7 padding."""

    padded = b"".join(
        decrypt_block(
            key,
            ciphertext[offset : offset + BLOCK_SIZE],
            sbox=sbox,
            rounds=rounds,
        )
        for offset in range(0, len(ciphertext), BLOCK_SIZE)
    )
    return pkcs7_unpad(padded)


def encrypt_cbc(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes:
    """Encrypt PKCS#7-padded plaintext using cipher block chaining."""

    padded = pkcs7_pad(plaintext)
    previous = iv
    ciphertext = bytearray()

    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset : offset + BLOCK_SIZE]
        encrypted = encrypt_block(
            key,
            xor_bytes(block, previous),
            sbox=sbox,
            rounds=rounds,
        )
        ciphertext.extend(encrypted)
        previous = encrypted

    return bytes(ciphertext)


def decrypt_cbc(
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes:
    """Decrypt CBC blocks and remove PKCS#7 padding."""

    previous = iv
    plaintext = bytearray()

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset : offset + BLOCK_SIZE]
        decrypted = decrypt_block(
            key,
            block,
            sbox=sbox,
            rounds=rounds,
        )
        plaintext.extend(xor_bytes(decrypted, previous))
        previous = block

    return pkcs7_unpad(bytes(plaintext))


def _transform_ctr(
    key: bytes,
    data: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes:
    transformed = bytearray()

    for counter, offset in enumerate(range(0, len(data), BLOCK_SIZE)):
        counter_block = iv + counter.to_bytes(CTR_COUNTER_SIZE, byteorder="big")
        keystream = encrypt_block(
            key,
            counter_block,
            sbox=sbox,
            rounds=rounds,
        )
        transformed.extend(
            xor_bytes(data[offset : offset + BLOCK_SIZE], keystream)
        )

    return bytes(transformed)


def encrypt_ctr(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes:
    """Encrypt bytes using SPN-generated CTR keystream blocks."""

    return _transform_ctr(key, plaintext, iv=iv, sbox=sbox, rounds=rounds)


def decrypt_ctr(
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes:
    """Decrypt CTR bytes by applying the same keystream transformation."""

    return _transform_ctr(key, ciphertext, iv=iv, sbox=sbox, rounds=rounds)
