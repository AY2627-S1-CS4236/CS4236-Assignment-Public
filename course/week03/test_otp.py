import importlib

import pytest


def _module():
    return importlib.import_module("educrypto.symmetric.otp")


def test_otp_round_trip():
    module = _module()
    pad = bytes.fromhex("001122334455")
    plaintext = b"secret"
    assert module.decrypt(pad, module.encrypt(pad, plaintext)) == plaintext


def test_otp_known_answer():
    module = _module()
    assert module.encrypt(b"\x0f\xaa", b"\xf0\x55") == b"\xff\xff"


def test_otp_rejects_repetition_and_text():
    module = _module()
    with pytest.raises(ValueError):
        module.encrypt(b"key", b"long message")
    with pytest.raises(TypeError):
        module.encrypt("key", "message")

