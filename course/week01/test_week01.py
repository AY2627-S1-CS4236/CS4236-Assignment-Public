import importlib
import secrets

import pytest


def _encoding():
    return importlib.import_module("educrypto.encoding")


def _otp():
    return importlib.import_module("educrypto.otp")


def test_encoding_public_api_exists():
    module = _encoding()
    for name in ("int_to_bytes", "bytes_to_int", "xor_bytes"):
        assert callable(getattr(module, name))


def test_integer_encoding_is_minimal_unsigned_big_endian():
    module = _encoding()
    assert module.int_to_bytes(0) == b"\x00"
    assert module.int_to_bytes(1) == b"\x01"
    assert module.int_to_bytes(0x1234) == b"\x12\x34"
    assert module.bytes_to_int(b"\x00\x12\x34") == 0x1234


def test_xor_truncates_to_shorter_input():
    module = _encoding()
    assert module.xor_bytes(b"\x0f\xaa", b"\xf0\x55") == b"\xff\xff"
    assert module.xor_bytes(b"abc", b"X") == b"9"
    assert module.xor_bytes(b"", b"anything") == b""


def test_otp_public_api_exists():
    module = _otp()
    assert callable(module.encrypt)
    assert callable(module.decrypt)


def test_otp_known_answer_and_round_trip():
    module = _otp()
    pad = bytes.fromhex("001122334455")
    plaintext = b"secret"
    expected = bytes(a ^ b for a, b in zip(pad, plaintext))
    ciphertext = module.encrypt(pad, plaintext)
    assert ciphertext == expected
    assert module.decrypt(pad, ciphertext) == plaintext


def test_otp_repeats_short_pads_and_truncates_long_pads():
    module = _otp()
    plaintext = b"repeat me"
    short_pad = b"key"
    repeated_pad = (short_pad * 3)[: len(plaintext)]
    expected = bytes(a ^ b for a, b in zip(plaintext, repeated_pad))
    ciphertext = module.encrypt(short_pad, plaintext)
    assert ciphertext == expected
    assert module.decrypt(short_pad, ciphertext) == plaintext

    long_pad = b"longer than the message"
    plaintext = b"short"
    expected = bytes(a ^ b for a, b in zip(plaintext, long_pad))
    ciphertext = module.encrypt(long_pad, plaintext)
    assert ciphertext == expected
    assert module.decrypt(long_pad, ciphertext) == plaintext


@pytest.mark.attack
def test_solver_recovers_environment_secret(monkeypatch):
    from course.week01.challenge.server import running_server

    secret = f"{secrets.token_hex(32)}"
    monkeypatch.setenv("SECRET", secret)

    attack = importlib.import_module("educrypto.attacks.week01")
    assert callable(attack.solve)

    with running_server() as server:
        recovered = attack.solve(server.base_url)

    assert isinstance(recovered, str)
    assert recovered == secret
