"""Public feedback for Week 10 Schnorr signatures and the EUF-CMA game."""

import dataclasses
import importlib
import inspect
import secrets

import pytest


def _schnorr():
    return importlib.import_module("educrypto.schnorr")


def _keys():
    dh = importlib.import_module("educrypto.dh")
    parameters = dh.DHParameters(p=467, g=4, q=233)
    return dh.DHPublicKey(parameters, 53), dh.DHPrivateKey(parameters, 37)


def test_public_type_and_signatures():
    schnorr = _schnorr()
    cls = schnorr.SchnorrSignature
    assert dataclasses.is_dataclass(cls)
    assert tuple(field.name for field in dataclasses.fields(cls)) == ("R", "s")
    assert cls.__dataclass_params__.frozen
    signature = cls(90, 83)
    assert not hasattr(signature, "__dict__")
    with pytest.raises(dataclasses.FrozenInstanceError):
        signature.s = 0
    for name, expected in (
        ("generate_keypair", ("parameters",)),
        ("hash", ("parameters", "R", "message")),
        ("sign", ("private_key", "message")),
        ("verify", ("public_key", "message", "signature")),
    ):
        assert tuple(inspect.signature(getattr(schnorr, name)).parameters) == expected


def test_keypair_uses_existing_dh_types_and_supplied_group():
    schnorr = _schnorr()
    dh = importlib.import_module("educrypto.dh")
    parameters = dh.generate_parameters(bits=64)
    public, private = schnorr.generate_keypair(parameters)
    assert isinstance(public, dh.DHPublicKey)
    assert isinstance(private, dh.DHPrivateKey)
    assert public.parameters is private.parameters is parameters
    assert 1 <= private.exponent < parameters.q
    assert public.value == pow(parameters.g, private.exponent, parameters.p)
    assert schnorr.verify(public, b"generated group", schnorr.sign(private, b"generated group"))


@pytest.mark.parametrize(
    ("message", "R", "s", "r"),
    (
        (b"CS4236", 90, 83, 21),
        (b"", 4, 117, 85),
        (b"\x00\x80\xff", 208, 149, 161),
        (b"zero nonce", 1, 15, 13),
        (b"\x00leading", 117, 94, 160),
    ),
)
def test_known_signatures_and_fixed_width_commitment(message, R, s, r):
    schnorr = _schnorr()
    public, _ = _keys()
    actual_r = schnorr.hash(public.parameters, R, message)
    assert type(actual_r) is int
    assert actual_r == r
    signature = schnorr.SchnorrSignature(R, s)
    assert schnorr.verify(public, message, signature) is True
    assert (signature.R, signature.s) == (R, s)


@pytest.mark.parametrize("message", (b"", b"\x00", b"\x00\x80\xff", bytes(range(256))))
def test_signing_uses_the_specified_sponge_and_preserves_inputs(message):
    schnorr = _schnorr()
    hashing = importlib.import_module("educrypto.hashing")
    public, private = _keys()
    before = dataclasses.astuple(private)
    signature = schnorr.sign(private, message)
    assert isinstance(signature, schnorr.SchnorrSignature)
    assert type(signature.R) is type(signature.s) is int
    assert 1 < signature.R < 467
    assert 0 <= signature.s < 233
    digest = hashing.sponge_hash(
        signature.R.to_bytes(2, "big") + message,
        c=8, digest_length=32, rounds=20,
    )
    r = int.from_bytes(digest, "big") % 233
    assert pow(4, signature.s, 467) == signature.R * pow(53, r, 467) % 467
    assert schnorr.verify(public, message, signature) is True
    assert dataclasses.astuple(private) == before


def test_repeated_message_uses_fresh_nonces():
    schnorr = _schnorr()
    public, private = _keys()
    signatures = [schnorr.sign(private, b"repeat") for _ in range(12)]
    assert all(schnorr.verify(public, b"repeat", signature) for signature in signatures)
    # Nonces need not be unique by chance; this only rejects a fixed nonce.
    assert len({signature.R for signature in signatures}) > 1


@pytest.mark.parametrize(
    ("R", "s"),
    ((0, 83), (-1, 83), (467, 83), (557, 83), (2, 83), (466, 83),
     (90, -1), (90, 233), (90, 316), (90, 84)),
)
def test_invalid_signatures_return_false(R, s):
    schnorr = _schnorr()
    public, _ = _keys()
    assert schnorr.verify(public, b"CS4236", schnorr.SchnorrSignature(R, s)) is False


def test_changed_message_and_wrong_public_key():
    schnorr = _schnorr()
    dh = importlib.import_module("educrypto.dh")
    public, _ = _keys()
    signature = schnorr.SchnorrSignature(90, 83)
    assert schnorr.verify(public, b"CS4237", signature) is False
    other = dh.DHPublicKey(public.parameters, pow(4, 38, 467))
    assert schnorr.verify(other, b"CS4236", signature) is False


def test_zero_response_can_be_a_valid_signature():
    schnorr = _schnorr()
    dh = importlib.import_module("educrypto.dh")
    public, _ = _keys()
    other = dh.DHPublicKey(public.parameters, 280)
    assert schnorr.verify(other, b"s zero", schnorr.SchnorrSignature(4, 0)) is True


@pytest.mark.attack
def test_solver_returns_exact_startup_secret():
    from course.week10.challenge.server import running_server

    attack = importlib.import_module("educrypto.attacks.week10")
    secret = f"Week 10 {secrets.token_hex(12)} — π 🔑"
    with running_server(secret=secret) as server:
        assert attack.solve(server.base_url) == secret
