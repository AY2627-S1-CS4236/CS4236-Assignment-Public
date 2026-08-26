import importlib
import secrets

import pytest


PUBLIC_FUNCTIONS = (
    "pkcs7_pad",
    "pkcs7_unpad",
    "encrypt_ecb",
    "decrypt_ecb",
    "encrypt_cbc",
    "decrypt_cbc",
    "encrypt_ctr",
    "decrypt_ctr",
)

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
CBC_IV = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
CTR_IV = bytes.fromhex("a0a1a2a3a4a5a6a7")
TEST_SBOX = bytes((45 * value + 77) % 256 for value in range(256))
ROUNDS = 4
PLAINTEXT = bytes.fromhex(
    "00112233445566778899aabbccddeeff112233445566778899"
)

ECB_VECTOR = bytes.fromhex(
    "70d92110799f2bd21fd9bef5fd89dc6c"
    "26733236b5cf5408d2a09fe5af4c33c7"
)
CBC_VECTOR = bytes.fromhex(
    "fa1f44c4eb03095db709c1b5b57dd098"
    "c6099d9b7ba9b5cb12c8787f7a6cd52b"
)
CTR_VECTOR = bytes.fromhex(
    "7e88352bfda9f3008a26dfe73673efdfed6f460df970e36ed9"
)


def _modes():
    return importlib.import_module("educrypto.modes")


def _configuration():
    return {"sbox": TEST_SBOX, "rounds": ROUNDS}


def test_public_api_exists():
    module = _modes()
    for name in PUBLIC_FUNCTIONS:
        assert callable(getattr(module, name))


@pytest.mark.parametrize(
    ("data", "expected"),
    (
        (b"", b"\x10" * 16),
        (b"A", b"A" + b"\x0f" * 15),
        (b"partial block", b"partial block" + b"\x03" * 3),
        (b"A" * 16, b"A" * 16 + b"\x10" * 16),
        (b"data\x00", b"data\x00" + b"\x0b" * 11),
    ),
)
def test_pkcs7_padding_api(data, expected):
    module = _modes()

    assert module.pkcs7_pad(data) == expected
    assert module.pkcs7_unpad(expected) == data


def test_ecb_known_answer_and_round_trip():
    module = _modes()
    encrypted = module.encrypt_ecb(KEY, PLAINTEXT, **_configuration())
    assert encrypted == ECB_VECTOR
    assert module.decrypt_ecb(KEY, encrypted, **_configuration()) == PLAINTEXT


def test_cbc_known_answer_and_round_trip():
    module = _modes()
    encrypted = module.encrypt_cbc(
        KEY,
        PLAINTEXT,
        iv=CBC_IV,
        **_configuration(),
    )
    assert encrypted == CBC_VECTOR
    assert module.decrypt_cbc(
        KEY,
        encrypted,
        iv=CBC_IV,
        **_configuration(),
    ) == PLAINTEXT


def test_ctr_known_answer_and_round_trip():
    module = _modes()
    encrypted = module.encrypt_ctr(
        KEY,
        PLAINTEXT,
        iv=CTR_IV,
        **_configuration(),
    )
    assert encrypted == CTR_VECTOR
    assert len(encrypted) == len(PLAINTEXT)
    assert module.decrypt_ctr(
        KEY,
        encrypted,
        iv=CTR_IV,
        **_configuration(),
    ) == PLAINTEXT


def test_ecb_and_cbc_apply_pkcs7_to_partial_and_aligned_plaintexts():
    module = _modes()
    short = b"partial block"
    aligned = b"A" * 16

    for encrypt, decrypt, extra in (
        (module.encrypt_ecb, module.decrypt_ecb, {}),
        (module.encrypt_cbc, module.decrypt_cbc, {"iv": CBC_IV}),
    ):
        short_ciphertext = encrypt(KEY, short, **extra, **_configuration())
        aligned_ciphertext = encrypt(KEY, aligned, **extra, **_configuration())

        assert len(short_ciphertext) == 16
        assert len(aligned_ciphertext) == 32
        assert decrypt(KEY, short_ciphertext, **extra, **_configuration()) == short
        assert decrypt(KEY, aligned_ciphertext, **extra, **_configuration()) == aligned


def test_pkcs7_encrypts_empty_messages_and_preserves_trailing_zero_bytes():
    module = _modes()

    ecb_empty = module.encrypt_ecb(KEY, b"", **_configuration())
    cbc_empty = module.encrypt_cbc(KEY, b"", iv=CBC_IV, **_configuration())
    assert len(ecb_empty) == 16
    assert len(cbc_empty) == 16
    assert module.decrypt_ecb(KEY, ecb_empty, **_configuration()) == b""
    assert module.decrypt_cbc(
        KEY,
        cbc_empty,
        iv=CBC_IV,
        **_configuration(),
    ) == b""
    assert module.encrypt_ctr(KEY, b"", iv=CTR_IV, **_configuration()) == b""
    assert module.decrypt_ctr(KEY, b"", iv=CTR_IV, **_configuration()) == b""

    ciphertext = module.encrypt_ecb(KEY, b"data\x00", **_configuration())
    assert module.decrypt_ecb(KEY, ciphertext, **_configuration()) == b"data\x00"


def test_ecb_reveals_repeated_blocks_while_cbc_chains_them():
    module = _modes()
    repeated_block = b"repeated-block!!"
    plaintext = repeated_block * 2

    ecb = module.encrypt_ecb(KEY, plaintext, **_configuration())
    cbc = module.encrypt_cbc(
        KEY,
        plaintext,
        iv=CBC_IV,
        **_configuration(),
    )

    assert ecb[:16] == ecb[16:32]
    assert cbc[:16] != cbc[16:32]


@pytest.mark.parametrize("length", (1, 15, 16, 17, 31, 32, 33))
def test_ctr_preserves_arbitrary_lengths(length):
    module = _modes()
    plaintext = bytes(range(length))
    ciphertext = module.encrypt_ctr(
        KEY,
        plaintext,
        iv=CTR_IV,
        **_configuration(),
    )

    assert len(ciphertext) == length
    assert module.decrypt_ctr(
        KEY,
        ciphertext,
        iv=CTR_IV,
        **_configuration(),
    ) == plaintext


def test_ctr_uses_an_eight_byte_big_endian_counter_starting_at_zero():
    module = _modes()
    spn = importlib.import_module("educrypto.spn")
    plaintext = bytes(range(32))
    expected = bytearray()

    for counter, offset in enumerate((0, 16)):
        counter_block = CTR_IV + counter.to_bytes(8, byteorder="big")
        stream = spn.encrypt_block(
            KEY,
            counter_block,
            **_configuration(),
        )
        expected.extend(
            left ^ right
            for left, right in zip(plaintext[offset : offset + 16], stream)
        )

    assert module.encrypt_ctr(
        KEY,
        plaintext,
        iv=CTR_IV,
        **_configuration(),
    ) == bytes(expected)


def test_mode_inputs_are_not_modified():
    module = _modes()
    key = bytes(KEY)
    plaintext = bytes(PLAINTEXT)
    cbc_iv = bytes(CBC_IV)
    ctr_iv = bytes(CTR_IV)
    sbox = bytes(TEST_SBOX)
    snapshots = (key[:], plaintext[:], cbc_iv[:], ctr_iv[:], sbox[:])

    ecb = module.encrypt_ecb(key, plaintext, sbox=sbox, rounds=ROUNDS)
    module.decrypt_ecb(key, ecb, sbox=sbox, rounds=ROUNDS)
    cbc = module.encrypt_cbc(
        key,
        plaintext,
        iv=cbc_iv,
        sbox=sbox,
        rounds=ROUNDS,
    )
    module.decrypt_cbc(
        key,
        cbc,
        iv=cbc_iv,
        sbox=sbox,
        rounds=ROUNDS,
    )
    ctr = module.encrypt_ctr(
        key,
        plaintext,
        iv=ctr_iv,
        sbox=sbox,
        rounds=ROUNDS,
    )
    module.decrypt_ctr(
        key,
        ctr,
        iv=ctr_iv,
        sbox=sbox,
        rounds=ROUNDS,
    )

    assert (key, plaintext, cbc_iv, ctr_iv, sbox) == snapshots

@pytest.mark.attack
def test_solver_wins_the_rcpa_game(monkeypatch):
    from course.week03.challenge.server import running_server

    secret = secrets.token_hex(32)
    monkeypatch.setenv("SECRET", secret)

    attack = importlib.import_module("educrypto.attacks.week03")
    assert callable(attack.solve)

    with running_server() as server:
        recovered = attack.solve(server.base_url)

    assert isinstance(recovered, str)
    assert recovered == secret
