import importlib

import pytest


def _module():
    return importlib.import_module("educrypto.encoding")


def test_public_api_exists():
    module = _module()
    for name in ("int_to_bytes", "bytes_to_int", "xor_bytes"):
        assert callable(getattr(module, name))


def test_minimal_big_endian_integer_encoding():
    module = _module()
    assert module.int_to_bytes(0) == b"\x00"
    assert module.int_to_bytes(0x1234) == b"\x12\x34"
    assert module.int_to_bytes(1, 4) == b"\x00\x00\x00\x01"
    assert module.bytes_to_int(b"") == 0
    assert module.bytes_to_int(b"\x12\x34") == 0x1234


def test_integer_encoding_rejects_invalid_values():
    module = _module()
    with pytest.raises(ValueError):
        module.int_to_bytes(-1)
    with pytest.raises(ValueError):
        module.int_to_bytes(256, 1)
    with pytest.raises(ValueError):
        module.int_to_bytes(0, 0)
    with pytest.raises(TypeError):
        module.bytes_to_int("not bytes")


def test_xor_bytes_contract():
    module = _module()
    assert module.xor_bytes(b"\x0f\xaa", b"\xf0\x55") == b"\xff\xff"
    with pytest.raises(ValueError):
        module.xor_bytes(b"a", b"ab")
    with pytest.raises(TypeError):
        module.xor_bytes("a", "b")

