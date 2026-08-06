import importlib

import pytest


def _module():
    return importlib.import_module("educrypto.symmetric.cbc")


def test_nist_first_block_vector():
    module = _module()
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
    assert module.encrypt(key, iv, plaintext) == expected
    assert module.decrypt(key, iv, expected) == plaintext


def test_cbc_round_trip_changes_equal_blocks():
    module = _module()
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    plaintext = b"A" * 32
    ciphertext = module.encrypt(key, iv, plaintext)
    assert module.decrypt(key, iv, ciphertext) == plaintext
    assert ciphertext[:16] != ciphertext[16:]


def test_cbc_rejects_invalid_sizes():
    module = _module()
    with pytest.raises(ValueError):
        module.encrypt(b"short", b"i" * 16, b"\x00" * 16)
    with pytest.raises(ValueError):
        module.encrypt(b"k" * 16, b"short", b"\x00" * 16)
    with pytest.raises(ValueError):
        module.encrypt(b"k" * 16, b"i" * 16, b"not aligned")

