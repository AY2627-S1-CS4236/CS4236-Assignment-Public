"""Public feedback for Week 08 Diffie–Hellman and the ElGamal game."""

import dataclasses
import importlib
import inspect
import secrets

import pytest


def _dh():
    return importlib.import_module("educrypto.dh")


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (0, False),
        (1, False),
        (2, True),
        (53, True),
        (561, False),
        (1105, False),
        (1729, False),
        ((1 << 61) - 1, True),
        (3 * ((1 << 61) - 1), False),
    ),
)
def test_supplied_probable_prime_helper(value, expected):
    primality = importlib.import_module("educrypto.primality")
    assert primality.is_probable_prime(value) is expected


def test_public_types_and_function_signatures():
    dh = _dh()
    for name, fields in (
        ("DHParameters", ("p", "g", "q")),
        ("DHPublicKey", ("parameters", "value")),
        ("DHPrivateKey", ("parameters", "exponent")),
    ):
        cls = getattr(dh, name)
        assert dataclasses.is_dataclass(cls)
        assert tuple(field.name for field in dataclasses.fields(cls)) == fields
        assert cls.__dataclass_params__.frozen

    generate_parameters = inspect.signature(dh.generate_parameters).parameters
    assert tuple(generate_parameters) == ("bits",)
    assert generate_parameters["bits"].kind is inspect.Parameter.KEYWORD_ONLY
    assert generate_parameters["bits"].default == 256
    assert tuple(inspect.signature(dh.generate_keypair).parameters) == ("parameters",)
    assert tuple(inspect.signature(dh.derive_shared_key).parameters) == (
        "private_key",
        "peer_public_key",
    )
    kdf = inspect.signature(dh.derive_shared_key_bytes).parameters
    assert tuple(kdf) == ("shared_key", "length")
    assert kdf["length"].kind is inspect.Parameter.KEYWORD_ONLY
    assert kdf["length"].default is inspect.Parameter.empty


def test_generated_safe_prime_subgroup_and_two_party_agreement():
    dh = _dh()
    parameters = dh.generate_parameters(bits=64)
    alice_public, alice_private = dh.generate_keypair(parameters)
    p, g, q = parameters.p, parameters.g, parameters.q
    assert all(type(value) is int for value in (p, g, q))
    assert p.bit_length() == 64
    assert p == 2 * q + 1
    assert importlib.import_module("educrypto.primality").is_probable_prime(p)
    assert importlib.import_module("educrypto.primality").is_probable_prime(q)
    assert 1 < g < p - 1 and pow(g, q, p) == 1
    assert 1 <= alice_private.exponent < q
    assert alice_public.value == pow(g, alice_private.exponent, p)

    bob_public, bob_private = dh.generate_keypair(parameters)
    assert bob_public.parameters == parameters
    alice_shared = dh.derive_shared_key(alice_private, bob_public)
    bob_shared = dh.derive_shared_key(bob_private, alice_public)
    assert type(alice_shared) is int
    assert alice_shared == bob_shared
    assert alice_shared == pow(g, alice_private.exponent * bob_private.exponent, p)
    assert dh.derive_shared_key_bytes(alice_shared, length=32) == dh.derive_shared_key_bytes(
        bob_shared, length=32
    )


@pytest.mark.parametrize("shared_key", (1, 255, 256, 65535, 65536))
@pytest.mark.parametrize("length", (16, 24, 32, 33))
def test_sponge_kdf_uses_week_one_encoding_and_twenty_rounds(shared_key, length):
    dh = _dh()
    encoding = importlib.import_module("educrypto.encoding")
    hashing = importlib.import_module("educrypto.hashing")
    expected = hashing.sponge_hash(
        encoding.int_to_bytes(shared_key),
        c=8,
        digest_length=length,
        rounds=20,
    )
    actual = dh.derive_shared_key_bytes(shared_key, length=length)
    assert isinstance(actual, bytes)
    assert len(actual) == length
    assert actual == expected


def test_keypair_reuses_supplied_group():
    dh = _dh()
    parameters = dh.DHParameters(31, 5, 3)
    public, private = dh.generate_keypair(parameters)
    assert public.parameters == private.parameters == parameters
    assert dh.derive_shared_key(private, public) == pow(public.value, private.exponent, 31)


@pytest.mark.attack
def test_solver_wins_thirty_rounds_and_returns_exact_secret():
    from course.week08.challenge.server import running_server

    secret = f"Week 08 {secrets.token_hex(12)} — π 🔑"
    attack = importlib.import_module("educrypto.attacks.week08")
    assert callable(attack.solve)
    with running_server(secret=secret) as server:
        assert attack.solve(server.base_url) == secret
