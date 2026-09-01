import importlib
import inspect
import secrets

import pytest


PUBLIC_FUNCTIONS = ("cmac", "verify_cmac", "pfmac", "verify_pfmac")
KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FINAL_KEY = bytes.fromhex("f0e0d0c0b0a090807060504030201000")
CMAC_KEY = KEY + FINAL_KEY
TEST_SBOX = bytes((45 * value + 77) % 256 for value in range(256))
ROUNDS = 4
ZERO_IV = bytes(16)

VECTORS = (
    (b"", "4e09e166911646244244c0760350c6d2", "87e1a1852d8f3b38278b4a727ed37aaa"),
    (
        b"message integrity",
        "df13f689b791f312636fc0f175f0d72c",
        "a419e714299b217b995a3d747f105673",
    ),
    (
        bytes(range(16)),
        "b1fdd17d957396adcb218c367509035d",
        "b2170bc5d805bde222c59e81a0d3830f",
    ),
    (
        bytes(range(40)),
        "186ea6eff41a0ce7a053b0a8e610f0b9",
        "e1a47e8da7e7295c4cb476a8d4816f60",
    ),
)


def _mac():
    return importlib.import_module("educrypto.mac")


def _configuration():
    return {"sbox": TEST_SBOX, "rounds": ROUNDS}


def test_public_api_exists_with_expected_parameters():
    module = _mac()
    expected = {
        "cmac": ("key", "message", "sbox", "rounds"),
        "verify_cmac": ("key", "message", "tag", "sbox", "rounds"),
        "pfmac": ("key", "message", "sbox", "rounds"),
        "verify_pfmac": ("key", "message", "tag", "sbox", "rounds"),
    }

    for name in PUBLIC_FUNCTIONS:
        function = getattr(module, name)
        assert callable(function)
        parameters = inspect.signature(function).parameters
        assert tuple(parameters) == expected[name]
        assert parameters["sbox"].kind is inspect.Parameter.KEYWORD_ONLY
        assert parameters["rounds"].kind is inspect.Parameter.KEYWORD_ONLY


@pytest.mark.parametrize(("message", "cmac_hex", "pfmac_hex"), VECTORS)
def test_known_answer_vectors(message, cmac_hex, pfmac_hex):
    module = _mac()
    cmac_tag = module.cmac(CMAC_KEY, message, **_configuration())
    pfmac_tag = module.pfmac(KEY, message, **_configuration())

    assert cmac_tag == bytes.fromhex(cmac_hex)
    assert pfmac_tag == bytes.fromhex(pfmac_hex)
    assert isinstance(cmac_tag, bytes) and len(cmac_tag) == 16
    assert isinstance(pfmac_tag, bytes) and len(pfmac_tag) == 16


def test_cmac_masks_only_the_final_padded_block():
    module = _mac()
    modes = importlib.import_module("educrypto.modes")
    spn = importlib.import_module("educrypto.spn")
    message = bytes(range(40))
    padded = modes.pkcs7_pad(message)
    previous = bytes(16)

    for offset in range(0, len(padded), 16):
        block = padded[offset : offset + 16]
        if offset == len(padded) - 16:
            block = bytes(left ^ right for left, right in zip(block, FINAL_KEY))
        cipher_input = bytes(left ^ right for left, right in zip(block, previous))
        previous = spn.encrypt_block(KEY, cipher_input, **_configuration())

    assert module.cmac(CMAC_KEY, message, **_configuration()) == previous


@pytest.mark.parametrize(
    ("length", "padded_blocks"),
    ((0, 1), (15, 1), (16, 2), (31, 2), (32, 3), (40, 3)),
)
def test_pfmac_prepends_big_endian_padded_block_count(length, padded_blocks):
    module = _mac()
    modes = importlib.import_module("educrypto.modes")
    message = bytes(index % 256 for index in range(length))
    encoded_count = padded_blocks.to_bytes(16, byteorder="big")
    ciphertext = modes.encrypt_cbc(
        KEY,
        encoded_count + message,
        iv=ZERO_IV,
        **_configuration(),
    )

    assert module.pfmac(KEY, message, **_configuration()) == ciphertext[-16:]


def test_verification_accepts_only_the_matching_message_and_tag():
    module = _mac()
    message = b"authenticated message"
    changed = b"authenticated messagf"
    cmac_tag = module.cmac(CMAC_KEY, message, **_configuration())
    pfmac_tag = module.pfmac(KEY, message, **_configuration())

    assert module.verify_cmac(CMAC_KEY, message, cmac_tag, **_configuration())
    assert not module.verify_cmac(CMAC_KEY, changed, cmac_tag, **_configuration())
    assert not module.verify_cmac(CMAC_KEY, message, cmac_tag[:-1], **_configuration())
    assert module.verify_pfmac(KEY, message, pfmac_tag, **_configuration())
    assert not module.verify_pfmac(KEY, changed, pfmac_tag, **_configuration())
    assert not module.verify_pfmac(KEY, message, pfmac_tag + b"\x00", **_configuration())


def test_both_cmac_key_halves_affect_the_tag():
    module = _mac()
    message = b"key separation"
    original = module.cmac(CMAC_KEY, message, **_configuration())
    changed_encryption_key = bytes([CMAC_KEY[0] ^ 1]) + CMAC_KEY[1:]
    changed_final_key = CMAC_KEY[:16] + bytes([CMAC_KEY[16] ^ 1]) + CMAC_KEY[17:]

    assert module.cmac(changed_encryption_key, message, **_configuration()) != original
    assert module.cmac(changed_final_key, message, **_configuration()) != original


def test_mac_inputs_are_not_modified():
    module = _mac()
    cmac_key = bytes(CMAC_KEY)
    key = bytes(KEY)
    message = bytes(range(40))
    sbox = bytes(TEST_SBOX)
    snapshots = (cmac_key[:], key[:], message[:], sbox[:])

    cmac_tag = module.cmac(cmac_key, message, sbox=sbox, rounds=ROUNDS)
    module.verify_cmac(cmac_key, message, cmac_tag, sbox=sbox, rounds=ROUNDS)
    pfmac_tag = module.pfmac(key, message, sbox=sbox, rounds=ROUNDS)
    module.verify_pfmac(key, message, pfmac_tag, sbox=sbox, rounds=ROUNDS)

    assert (cmac_key, key, message, sbox) == snapshots


@pytest.mark.attack
def test_solver_wins_the_euf_cma_game(monkeypatch):
    from course.week04.challenge.server import running_server

    secret = secrets.token_hex(32)
    monkeypatch.setenv("SECRET", secret)

    attack = importlib.import_module("educrypto.attacks.week04")
    assert callable(attack.solve)

    with running_server() as server:
        recovered = attack.solve(server.base_url)

    assert isinstance(recovered, str)
    assert recovered == secret
