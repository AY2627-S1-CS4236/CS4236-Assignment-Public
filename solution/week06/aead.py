"""Authenticated-encryption constructions assembled from earlier course work."""

from __future__ import annotations

from .hashing import AES_SBOX, merkle_damgard
from .mac import cmac, verify_cmac
from .modes import decrypt_ctr, encrypt_ctr


CTR_KEY_BYTES = 16
TAG_BYTES = 16


def _pad_associated_data(associated_data: bytes) -> bytes:
    """Append one 1 bit and zero bits to make one 16-byte block."""

    return associated_data + b"\x80" + bytes(15 - len(associated_data))


def _keys(key: bytes) -> tuple[bytes, bytes]:
    """Split the course AEAD key into its CTR and CMAC portions."""

    return key[:CTR_KEY_BYTES], key[CTR_KEY_BYTES:]


def encrypt_mte(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> tuple[bytes, bytes, bytes]:
    """Authenticate IV, associated data, and plaintext before CTR encryption."""

    encryption_key, mac_key = _keys(key)
    padded_associated_data = _pad_associated_data(associated_data)
    tag = cmac(
        mac_key,
        iv + padded_associated_data + plaintext,
        sbox=sbox,
        rounds=rounds,
    )
    ciphertext = encrypt_ctr(
        encryption_key,
        tag + plaintext,
        iv=iv,
        sbox=sbox,
        rounds=rounds,
    )
    return iv, associated_data, ciphertext


def decrypt_mte(
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes | None:
    """Decrypt an MTE payload and return plaintext only after authentication."""

    encryption_key, mac_key = _keys(key)
    combined = decrypt_ctr(
        encryption_key,
        ciphertext,
        iv=iv,
        sbox=sbox,
        rounds=rounds,
    )
    received_tag = combined[:TAG_BYTES]
    plaintext = combined[TAG_BYTES:]
    padded_associated_data = _pad_associated_data(associated_data)
    if not verify_cmac(
        mac_key,
        iv + padded_associated_data + plaintext,
        received_tag,
        sbox=sbox,
        rounds=rounds,
    ):
        return None
    return plaintext


def encrypt_etm(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> tuple[bytes, bytes, bytes, bytes]:
    """Encrypt with CTR, hash the public data, and authenticate the digest."""

    encryption_key, mac_key = _keys(key)
    ciphertext = encrypt_ctr(
        encryption_key,
        plaintext,
        iv=iv,
        sbox=sbox,
        rounds=rounds,
    )
    padded_associated_data = _pad_associated_data(associated_data)
    digest = merkle_damgard(
        padded_associated_data + iv + ciphertext,
        sbox=sbox,
        rounds=rounds,
    )
    tag = cmac(mac_key, digest, sbox=sbox, rounds=rounds)
    return iv, associated_data, ciphertext, tag


def decrypt_etm(
    key: bytes,
    ciphertext: bytes,
    tag: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes | None:
    """Verify an ETM payload before applying the CTR transformation."""

    encryption_key, mac_key = _keys(key)
    padded_associated_data = _pad_associated_data(associated_data)
    digest = merkle_damgard(
        padded_associated_data + iv + ciphertext,
        sbox=sbox,
        rounds=rounds,
    )
    if not verify_cmac(
        mac_key,
        digest,
        tag,
        sbox=sbox,
        rounds=rounds,
    ):
        return None
    return decrypt_ctr(
        encryption_key,
        ciphertext,
        iv=iv,
        sbox=sbox,
        rounds=rounds,
    )
