import importlib
import inspect
import secrets

import pytest


KEY = bytes(range(48))
IV = bytes.fromhex("1020304050607080")
AD = bytes.fromhex("00112233445566778899aabbccddee")
TEST_SBOX = bytes((45 * value + 77) % 256 for value in range(256))

VECTORS = (
    (
        b"",
        "df25a3314482f86714df349a97c9ffd0",
        "",
        "cc70419a25b693ec0d4bc83b124294a6",
    ),
    (
        b"hello, AEAD!",
        "a3aef4c0a8170a2c87d54ccbcb91bd027c3b392380916d3cc689e8c0",
        "60577e07f560168114376518",
        "c17f3c397286feef145d9959d6f0d622",
    ),
    (
        bytes(range(31)),
        "447695e86f3c56985bb773414e092a81"
        "145f574cebb84b7a8bc1a6ea2b4b1406"
        "fca232b3d8e3045c70b5fcd6348f3c",
        "083310689e4930c7597f2b322932c317"
        "044f475cfba85b6a9bd1b6fa3b5b04",
        "aadd925e829a14ee2b5c99fce995fb51",
    ),
)


def _aead():
    return importlib.import_module("educrypto.aead")


def _flip(value, index=0):
    changed = bytearray(value)
    changed[index] ^= 1
    return bytes(changed)


def test_public_api_signatures_and_defaults():
    module = _aead()
    expected = {
        "encrypt_mte": (
            "key",
            "plaintext",
            "iv",
            "associated_data",
            "sbox",
            "rounds",
        ),
        "decrypt_mte": (
            "key",
            "ciphertext",
            "iv",
            "associated_data",
            "sbox",
            "rounds",
        ),
        "encrypt_etm": (
            "key",
            "plaintext",
            "iv",
            "associated_data",
            "sbox",
            "rounds",
        ),
        "decrypt_etm": (
            "key",
            "ciphertext",
            "tag",
            "iv",
            "associated_data",
            "sbox",
            "rounds",
        ),
    }
    for name, parameter_names in expected.items():
        parameters = inspect.signature(getattr(module, name)).parameters
        assert tuple(parameters) == parameter_names
        assert parameters["sbox"].default == importlib.import_module(
            "educrypto.hashing"
        ).AES_SBOX
        assert parameters["rounds"].default is inspect.Parameter.empty
        assert all(
            parameters[field].kind is inspect.Parameter.KEYWORD_ONLY
            for field in ("iv", "associated_data", "sbox", "rounds")
        )


@pytest.mark.parametrize(
    ("message", "mte_ciphertext_hex", "etm_ciphertext_hex", "etm_tag_hex"),
    VECTORS,
)
def test_known_answers(
    message,
    mte_ciphertext_hex,
    etm_ciphertext_hex,
    etm_tag_hex,
):
    module = _aead()
    assert module.encrypt_mte(
        KEY,
        message,
        iv=IV,
        associated_data=AD,
        rounds=10,
    ) == (IV, AD, bytes.fromhex(mte_ciphertext_hex))
    assert module.encrypt_etm(
        KEY,
        message,
        iv=IV,
        associated_data=AD,
        rounds=10,
    ) == (
        IV,
        AD,
        bytes.fromhex(etm_ciphertext_hex),
        bytes.fromhex(etm_tag_hex),
    )


def test_mte_authenticates_then_encrypts_tag_as_first_block():
    aead = _aead()
    modes = importlib.import_module("educrypto.modes")
    mac = importlib.import_module("educrypto.mac")
    message = bytes(range(37))
    tag = mac.cmac(
        KEY[16:],
        IV + AD + b"\x80" + message,
        sbox=TEST_SBOX,
        rounds=4,
    )
    expected = modes.encrypt_ctr(
        KEY[:16],
        tag + message,
        iv=IV,
        sbox=TEST_SBOX,
        rounds=4,
    )
    output = aead.encrypt_mte(
        KEY,
        message,
        iv=IV,
        associated_data=AD,
        sbox=TEST_SBOX,
        rounds=4,
    )
    assert output == (IV, AD, expected)
    assert len(output[2]) == len(message) + 16
    assert modes.decrypt_ctr(
        KEY[:16],
        output[2][:16],
        iv=IV,
        sbox=TEST_SBOX,
        rounds=4,
    ) == tag


def test_etm_encrypts_from_counter_zero_then_hashes_and_authenticates():
    aead = _aead()
    modes = importlib.import_module("educrypto.modes")
    mac = importlib.import_module("educrypto.mac")
    hashing = importlib.import_module("educrypto.hashing")
    message = bytes(range(37))
    ciphertext = modes.encrypt_ctr(
        KEY[:16],
        message,
        iv=IV,
        sbox=TEST_SBOX,
        rounds=4,
    )
    digest = hashing.merkle_damgard(
        AD + b"\x80" + IV + ciphertext,
        sbox=TEST_SBOX,
        rounds=4,
    )
    tag = mac.cmac(
        KEY[16:],
        digest,
        sbox=TEST_SBOX,
        rounds=4,
    )
    assert aead.encrypt_etm(
        KEY,
        message,
        iv=IV,
        associated_data=AD,
        sbox=TEST_SBOX,
        rounds=4,
    ) == (IV, AD, ciphertext, tag)


@pytest.mark.parametrize("length", (0, 1, 15, 16, 17, 31, 32, 79, 4097))
def test_round_trips_arbitrary_lengths(length):
    module = _aead()
    message = bytes(index % 256 for index in range(length))
    mte_iv, mte_ad, mte_ciphertext = module.encrypt_mte(
        KEY,
        message,
        iv=IV,
        associated_data=AD,
        sbox=TEST_SBOX,
        rounds=4,
    )
    assert module.decrypt_mte(
        KEY,
        mte_ciphertext,
        iv=mte_iv,
        associated_data=mte_ad,
        sbox=TEST_SBOX,
        rounds=4,
    ) == message

    etm_iv, etm_ad, etm_ciphertext, tag = module.encrypt_etm(
        KEY,
        message,
        iv=IV,
        associated_data=AD,
        sbox=TEST_SBOX,
        rounds=4,
    )
    assert len(etm_ciphertext) == len(message)
    assert module.decrypt_etm(
        KEY,
        etm_ciphertext,
        tag,
        iv=etm_iv,
        associated_data=etm_ad,
        sbox=TEST_SBOX,
        rounds=4,
    ) == message


@pytest.mark.parametrize("associated_data", (b"", b"A", bytes(range(14)), bytes(range(15))))
def test_associated_data_is_padded_to_one_block_and_returned_unchanged(
    associated_data,
):
    module = _aead()
    modes = importlib.import_module("educrypto.modes")
    mac = importlib.import_module("educrypto.mac")
    hashing = importlib.import_module("educrypto.hashing")
    message = b"associated-data padding"
    padded_ad = associated_data + b"\x80" + bytes(15 - len(associated_data))
    expected_tag = mac.cmac(
        KEY[16:],
        IV + padded_ad + message,
        sbox=TEST_SBOX,
        rounds=4,
    )
    expected_ciphertext = modes.encrypt_ctr(
        KEY[:16],
        expected_tag + message,
        iv=IV,
        sbox=TEST_SBOX,
        rounds=4,
    )
    assert module.encrypt_mte(
        KEY,
        message,
        iv=IV,
        associated_data=associated_data,
        sbox=TEST_SBOX,
        rounds=4,
    ) == (IV, associated_data, expected_ciphertext)

    etm_output = module.encrypt_etm(
        KEY,
        message,
        iv=IV,
        associated_data=associated_data,
        sbox=TEST_SBOX,
        rounds=4,
    )
    assert etm_output[1] == associated_data
    expected_etm_ciphertext = modes.encrypt_ctr(
        KEY[:16],
        message,
        iv=IV,
        sbox=TEST_SBOX,
        rounds=4,
    )
    expected_digest = hashing.merkle_damgard(
        padded_ad + IV + expected_etm_ciphertext,
        sbox=TEST_SBOX,
        rounds=4,
    )
    expected_etm_tag = mac.cmac(
        KEY[16:],
        expected_digest,
        sbox=TEST_SBOX,
        rounds=4,
    )
    assert etm_output == (
        IV,
        associated_data,
        expected_etm_ciphertext,
        expected_etm_tag,
    )
    assert module.decrypt_etm(
        KEY,
        etm_output[2],
        etm_output[3],
        iv=IV,
        associated_data=associated_data,
        sbox=TEST_SBOX,
        rounds=4,
    ) == message


def test_mte_rejects_valid_size_tampering():
    module = _aead()
    message = bytes(range(48))
    iv, ad, ciphertext = module.encrypt_mte(
        KEY,
        message,
        iv=IV,
        associated_data=AD,
        rounds=10,
    )
    assert module.decrypt_mte(
        KEY, ciphertext, iv=_flip(iv), associated_data=ad, rounds=10
    ) is None
    assert module.decrypt_mte(
        KEY, ciphertext, iv=iv, associated_data=_flip(ad), rounds=10
    ) is None
    assert module.decrypt_mte(
        KEY, _flip(ciphertext, 20), iv=iv, associated_data=ad, rounds=10
    ) is None


def test_etm_rejects_valid_size_tampering():
    module = _aead()
    message = bytes(range(48))
    iv, ad, ciphertext, tag = module.encrypt_etm(
        KEY,
        message,
        iv=IV,
        associated_data=AD,
        rounds=10,
    )
    assert module.decrypt_etm(
        KEY, ciphertext, tag, iv=_flip(iv), associated_data=ad, rounds=10
    ) is None
    assert module.decrypt_etm(
        KEY, ciphertext, tag, iv=iv, associated_data=_flip(ad), rounds=10
    ) is None
    assert module.decrypt_etm(
        KEY, _flip(ciphertext, 20), tag, iv=iv, associated_data=ad, rounds=10
    ) is None
    assert module.decrypt_etm(
        KEY, ciphertext, _flip(tag), iv=iv, associated_data=ad, rounds=10
    ) is None


def test_calls_are_independent_and_inputs_are_preserved():
    module = _aead()
    key, iv, ad, message = KEY[:], IV[:], AD[:], bytes(range(40))
    snapshots = key[:], iv[:], ad[:], message[:]
    first_mte = module.encrypt_mte(
        key, message, iv=iv, associated_data=ad, rounds=10
    )
    first_etm = module.encrypt_etm(
        key, message, iv=iv, associated_data=ad, rounds=10
    )
    module.encrypt_mte(key, b"unrelated", iv=iv, associated_data=ad, rounds=10)
    module.encrypt_etm(key, b"other", iv=iv, associated_data=ad, rounds=10)
    assert module.encrypt_mte(
        key, message, iv=iv, associated_data=ad, rounds=10
    ) == first_mte
    assert module.encrypt_etm(
        key, message, iv=iv, associated_data=ad, rounds=10
    ) == first_etm
    assert (key, iv, ad, message) == snapshots


@pytest.mark.attack
def test_solver_wins_cca_game_and_recovers_unicode_secret():
    from course.week06.challenge.server import running_server

    secret = f"Week 06 {secrets.token_hex(24)} — π"
    attack = importlib.import_module("educrypto.attacks.week06")
    assert callable(attack.solve)
    with running_server(secret=secret) as server:
        recovered = attack.solve(server.base_url)
    assert isinstance(recovered, str)
    assert recovered == secret
