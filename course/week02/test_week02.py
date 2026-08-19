import importlib
import secrets

import pytest


PUBLIC_FUNCTIONS = (
    "substitute",
    "inverse_substitute",
    "permute",
    "inverse_permute",
    "expand_key",
    "encrypt_block",
    "decrypt_block",
)

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
IDENTITY_SBOX = bytes(range(256))
REVERSE_SBOX = bytes(reversed(range(256)))
TEST_SBOX = bytes((45 * value + 77) % 256 for value in range(256))

KEY_SCHEDULE = (
    "000102030405060708090a0b0c0d0e0f",
    "cd4dfa7a27a754d48101ae2edb5b0888",
    "3b7bc606a4642fef8dcd185876b68141",
    "e68634d4b71758b81bbbe909ac4c8d6d",
    "0414dfef4cbc897996263181ebfb9b4b",
)

BLOCK_VECTORS = (
    (1, "716156449989baa87d6d42502535a6b4"),
    (4, "70d92110799f2bd21fd9bef5fd89dc6c"),
    (10, "4a7f6326ee452eebd304f233c6bd2397"),
)


def _spn():
    return importlib.import_module("educrypto.spn")


def test_public_api_exists():
    module = _spn()
    assert module.BLOCK_SIZE == 16
    assert isinstance(module.BLOCK_SIZE, int)
    for name in PUBLIC_FUNCTIONS:
        assert callable(getattr(module, name))


def test_substitution_known_answer():
    module = _spn()
    expected = bytes.fromhex("4d4a4744413e3b3835322f2c29262320")

    result = module.substitute(PLAINTEXT, sbox=TEST_SBOX)
    assert result == expected
    assert isinstance(result, bytes)
    assert module.inverse_substitute(expected, sbox=TEST_SBOX) == PLAINTEXT


@pytest.mark.parametrize(
    "sbox",
    (IDENTITY_SBOX, REVERSE_SBOX, TEST_SBOX),
    ids=("identity", "reverse", "test-table"),
)
def test_substitution_and_inverse_round_trip(sbox):
    module = _spn()
    state = bytes(range(16))

    substituted = module.substitute(state, sbox=sbox)
    restored = module.inverse_substitute(substituted, sbox=sbox)

    assert isinstance(substituted, bytes)
    assert isinstance(restored, bytes)
    assert restored == state


def test_bit_permutation_known_answer():
    module = _spn()
    state = bytes(range(16))
    expected = bytes.fromhex("2c0509200c21290428010d2408252d00")

    permuted = module.permute(state)
    assert permuted == expected
    assert isinstance(permuted, bytes)
    assert module.inverse_permute(expected) == state


def test_bit_permutation_and_inverse_round_trip():
    module = _spn()
    states = (
        bytes(16),
        b"\xff" * 16,
        bytes(range(16)),
        bytes.fromhex("80000000000000000000000000000001"),
    )
    for state in states:
        assert module.inverse_permute(module.permute(state)) == state
        assert module.permute(module.inverse_permute(state)) == state


def test_key_expansion_known_answer():
    module = _spn()
    expected = tuple(bytes.fromhex(value) for value in KEY_SCHEDULE)

    expanded = module.expand_key(KEY, sbox=TEST_SBOX, rounds=4)

    assert isinstance(expanded, tuple)
    assert expanded == expected
    assert len(expanded) == 5
    assert all(isinstance(round_key, bytes) for round_key in expanded)


def test_key_expansion_rotates_the_complete_128_bit_key():
    module = _spn()
    key = bytes.fromhex("80000000000000000000000000000001")
    expanded = module.expand_key(key, sbox=IDENTITY_SBOX, rounds=1)

    assert expanded == (
        key,
        bytes.fromhex("c0000000000000000000000000000000"),
    )


@pytest.mark.parametrize("rounds, expected_hex", BLOCK_VECTORS)
def test_block_encryption_known_answers(rounds, expected_hex):
    module = _spn()
    expected = bytes.fromhex(expected_hex)

    encrypted = module.encrypt_block(
        KEY,
        PLAINTEXT,
        sbox=TEST_SBOX,
        rounds=rounds,
    )

    assert encrypted == expected
    assert isinstance(encrypted, bytes)
    assert module.decrypt_block(
        KEY,
        expected,
        sbox=TEST_SBOX,
        rounds=rounds,
    ) == PLAINTEXT


@pytest.mark.parametrize(
    "sbox, rounds",
    (
        (IDENTITY_SBOX, 1),
        (REVERSE_SBOX, 2),
        (TEST_SBOX, 10),
    ),
    ids=("identity-1", "reverse-2", "test-table-10"),
)
def test_block_encryption_round_trips_with_multiple_configurations(sbox, rounds):
    module = _spn()
    ciphertext = module.encrypt_block(KEY, PLAINTEXT, sbox=sbox, rounds=rounds)
    assert module.decrypt_block(KEY, ciphertext, sbox=sbox, rounds=rounds) == PLAINTEXT


def test_cryptographic_inputs_are_not_modified():
    module = _spn()
    key = bytes(KEY)
    state = bytes(PLAINTEXT)
    sbox = bytes(TEST_SBOX)
    snapshots = (key[:], state[:], sbox[:])

    module.substitute(state, sbox=sbox)
    module.inverse_substitute(state, sbox=sbox)
    module.permute(state)
    module.inverse_permute(state)
    module.expand_key(key, sbox=sbox, rounds=4)
    module.encrypt_block(key, state, sbox=sbox, rounds=4)
    module.decrypt_block(key, state, sbox=sbox, rounds=4)

    assert (key, state, sbox) == snapshots


@pytest.mark.attack
def test_solver_recovers_environment_secret(monkeypatch):
    from course.week02.challenge.server import running_server

    secret = secrets.token_hex(32)
    monkeypatch.setenv("SECRET", secret)

    attack = importlib.import_module("educrypto.attacks.week02")
    assert callable(attack.solve)

    with running_server() as server:
        recovered = attack.solve(server.base_url)

    assert isinstance(recovered, str)
    assert recovered == secret
