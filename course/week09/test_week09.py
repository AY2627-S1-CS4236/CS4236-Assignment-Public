"""Public feedback for Week 09 byte-string LWE public-key encryption."""

import dataclasses
import importlib
import inspect

import pytest


def _lwe():
    return importlib.import_module("educrypto.lwe")


def _helpers():
    return importlib.import_module("educrypto.lwe_helpers")


@pytest.fixture(scope="module")
def keypair():
    return _lwe().generate_keypair()


def test_parameter_defaults_types_and_signatures():
    lwe = _lwe()
    parameters = lwe.LWEParameters()
    for name, expected in (("p", 12289), ("n", 704), ("m", 10240), ("error_bound", 2)):
        assert type(getattr(parameters, name)) is int
        assert getattr(parameters, name) == expected
    for name, fields in (
        ("LWEParameters", ("p", "n", "m", "error_bound")),
        ("LWEPublicKey", ("parameters", "A", "t")),
        ("LWEPrivateKey", ("parameters", "s")),
        ("LWEBitCiphertext", ("u", "v")),
    ):
        cls = getattr(lwe, name)
        assert dataclasses.is_dataclass(cls)
        assert tuple(field.name for field in dataclasses.fields(cls)) == fields
        assert cls.__dataclass_params__.frozen
        assert cls.__slots__ == fields
    for name, parameter_names in (
        ("generate_keypair", ("parameters",)),
        ("encrypt", ("public_key", "plaintext")),
        ("decrypt", ("private_key", "ciphertext")),
    ):
        assert tuple(inspect.signature(getattr(lwe, name)).parameters) == parameter_names
    generate = inspect.signature(lwe.generate_keypair).parameters
    assert generate["parameters"].default == lwe.LWEParameters()
    helpers = _helpers()
    multiply = inspect.signature(helpers.matrix_multiply).parameters
    assert tuple(multiply) == ("left", "right", "modulus")
    assert multiply["modulus"].kind is inspect.Parameter.KEYWORD_ONLY
    assert multiply["modulus"].default is inspect.Parameter.empty
    for name, parameter in (("transpose", "matrix"), ("bytes_to_bits", "data"), ("bits_to_bytes", "bits")):
        assert tuple(inspect.signature(getattr(helpers, name)).parameters) == (parameter,)


def test_matrix_helpers_handle_rectangles_and_preserve_inputs():
    helpers = _helpers()
    left = [[1, 2, 3], [4, 5, 6]]
    right = [[7, 8], [9, 10], [11, 12]]
    assert helpers.matrix_multiply(left, right, modulus=17) == [[7, 13], [3, 1]]
    assert helpers.transpose(left) == [[1, 4], [2, 5], [3, 6]]
    assert helpers.transpose(helpers.transpose(left)) == left
    transposed = helpers.transpose(left)
    transposed[0][0] = 99
    assert left == [[1, 2, 3], [4, 5, 6]]
    assert right == [[7, 8], [9, 10], [11, 12]]
    assert helpers.matrix_multiply([[-1, 18], [34, -2]], [[3], [5]], modulus=17) == [[2], [7]]
    assert helpers.transpose([[0], [1]]) == [[0, 1]]


def test_byte_conversion_is_msb_first_and_preserves_leading_zeros():
    helpers = _helpers()
    assert helpers.bytes_to_bits(b"\x00\x81") == [0] * 8 + [1, 0, 0, 0, 0, 0, 0, 1]
    assert helpers.bits_to_bytes([0] * 7 + [1]) == b"\x01"
    assert helpers.bytes_to_bits(b"") == []
    assert helpers.bits_to_bytes([]) == b""
    data = bytes(range(256))
    bits = helpers.bytes_to_bits(data)
    assert type(bits) is list
    assert len(bits) == 8 * len(data)
    assert all(type(bit) is int and bit in (0, 1) for bit in bits)
    assert all(bits[8 * value + position] == ((value >> (7 - position)) & 1)
               for value in range(256) for position in range(8))
    snapshot = bits[:]
    assert helpers.bits_to_bytes(bits) == data
    assert bits == snapshot


def test_generated_key_shapes_residues_and_bounded_error(keypair):
    lwe = _lwe()
    public, private = keypair
    assert isinstance(public, lwe.LWEPublicKey)
    assert isinstance(private, lwe.LWEPrivateKey)
    parameters = public.parameters
    assert isinstance(parameters, lwe.LWEParameters)
    assert parameters == private.parameters == lwe.LWEParameters()
    assert type(public.A) is list and len(public.A) == parameters.m
    assert type(public.t) is list and len(public.t) == parameters.m
    assert type(private.s) is list and len(private.s) == parameters.n
    assert all(type(value) is int and 0 <= value < parameters.p for value in private.s)
    for row, value in zip(public.A, public.t):
        assert type(row) is list and len(row) == parameters.n
        assert all(type(entry) is int and 0 <= entry < parameters.p for entry in row)
        assert type(value) is int and 0 <= value < parameters.p
        residual = (value - sum(a * s for a, s in zip(row, private.s))) % parameters.p
        centered = residual if residual <= parameters.p // 2 else residual - parameters.p
        assert -parameters.error_bound <= centered <= parameters.error_bound


@pytest.mark.parametrize("message", (b"", b"\x00", b"\x80\xff"))
def test_short_byte_round_trips_and_ciphertext_shape(keypair, message):
    lwe = _lwe()
    public, private = keypair
    parameters = public.parameters
    ciphertext = lwe.encrypt(public, message)
    assert type(ciphertext) is list and len(ciphertext) == 8 * len(message)
    for bit in ciphertext:
        assert isinstance(bit, lwe.LWEBitCiphertext)
        assert type(bit.u) is list and len(bit.u) == parameters.n
        assert all(type(value) is int and 0 <= value < parameters.p for value in bit.u)
        assert type(bit.v) is int and 0 <= bit.v < parameters.p
    plaintext = lwe.decrypt(private, ciphertext)
    assert type(plaintext) is bytes and plaintext == message


def test_encryption_and_decryption_preserve_inputs(keypair):
    lwe = _lwe()
    public, private = keypair
    matrix_snapshot = [row[:] for row in public.A]
    t_snapshot, s_snapshot = public.t[:], private.s[:]
    message = b"\x01"
    ciphertext = lwe.encrypt(public, message)
    ciphertext_snapshot = [(bit.u[:], bit.v) for bit in ciphertext]
    assert lwe.decrypt(private, ciphertext) == message
    assert public.A == matrix_snapshot
    assert public.t == t_snapshot and private.s == s_snapshot
    assert [(bit.u, bit.v) for bit in ciphertext] == ciphertext_snapshot
