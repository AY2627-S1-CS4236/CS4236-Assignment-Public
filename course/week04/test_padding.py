import importlib

import pytest


def _module():
    return importlib.import_module("educrypto.symmetric.padding")


def test_pkcs7_examples():
    module = _module()
    assert module.pkcs7_pad(b"YELLOW SUBMARINE", 20) == (
        b"YELLOW SUBMARINE" + b"\x04" * 4
    )
    assert module.pkcs7_pad(b"", 16) == b"\x10" * 16
    assert module.pkcs7_pad(b"A" * 16, 16) == b"A" * 16 + b"\x10" * 16


def test_pkcs7_round_trip():
    module = _module()
    for length in range(40):
        message = bytes(range(length))
        assert module.pkcs7_unpad(module.pkcs7_pad(message, 16), 16) == message


@pytest.mark.parametrize(
    "invalid",
    [b"", b"ICE ICE BABY\x05\x05\x05\x05", b"ICE ICE BABY\x01\x02\x03\x04"],
)
def test_pkcs7_rejects_malformed_padding(invalid):
    with pytest.raises(ValueError):
        _module().pkcs7_unpad(invalid, 16)

