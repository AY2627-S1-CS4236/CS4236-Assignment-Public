import importlib

import pytest


def _module():
    return importlib.import_module("educrypto.symmetric.ecb")


def test_aes_zero_block_known_answer():
    module = _module()
    assert module.encrypt(b"\x00" * 16, b"\x00" * 16).hex() == (
        "66e94bd4ef8a2c3b884cfa59ca342b2e"
    )


def test_ecb_round_trip_and_equal_blocks():
    module = _module()
    key = bytes(range(16))
    plaintext = b"A" * 32
    ciphertext = module.encrypt(key, plaintext)
    assert module.decrypt(key, ciphertext) == plaintext
    assert ciphertext[:16] == ciphertext[16:]


def test_ecb_rejects_invalid_lengths():
    module = _module()
    with pytest.raises(ValueError):
        module.encrypt(b"short", b"\x00" * 16)
    with pytest.raises(ValueError):
        module.encrypt(b"k" * 16, b"not aligned")

