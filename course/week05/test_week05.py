import hashlib
import importlib
import inspect
import secrets

import pytest


H = bytes(range(16))
M = bytes.fromhex("00112233445566778899aabbccddeeff")
TEST_SBOX = bytes((45 * value + 77) % 256 for value in range(256))
IDENTITY_SBOX = bytes(range(256))

# Frozen answers calculated independently from the published Week 2 and Week 5
# recurrences. Messages are bytes(index % 256 for index in range(length)).
DM_VECTORS = (
    ("aes", 1, "0bcb215d483f6bfcdf025850cdba3c8d"),
    ("aes", 10, "aaf8580ddfb6d7b20fe012fca39b42e8"),
    ("test", 4, "f5c0946cd2586e9e92f75d77d18a04d8"),
    ("identity", 2, "fb916a33de946d14f19b6039d49e671e"),
)
MD_VECTORS = (
    (0, "aes", 10, "b1f4df280aa203d7652cd0ec08d764e1"),
    (1, "aes", 10, "6f5d81f49054ffb17b7321dcc6911c42"),
    (15, "aes", 10, "1e88829d2e1317c28d37c601fbc21f15"),
    (16, "aes", 10, "f59a20b058c4848e680f2aed0566b273"),
    (17, "aes", 10, "355a8be470b2e55b12b79b6d094002e8"),
    (31, "aes", 10, "26592d7ced056a290df1458f6b54cbab"),
    (32, "aes", 10, "d599c69ab9063d5407f79165cc8cb498"),
    (33, "aes", 10, "33589246a8097bca0b6611ca4cced3b9"),
    (4097, "aes", 10, "8d930078cc8bb27fab52807489c96330"),
    (40, "test", 4, "0e55489e4ce429c169e41b6102439f3d"),
    (16, "identity", 2, "6411ef915528de8ae63bcdb17508fe80"),
    (31, "aes", 1, "62dd20c4695bedaf0d8f1baca33e0be3"),
)
SPONGE_VECTORS = (
    (b"", 13, 3, "aes", 10, "5dd991"),
    (b"hello", 13, 3, "aes", 10, "3026e6"),
    (
        b"",
        3,
        32,
        "aes",
        10,
        "c2418705c0015173ab3fa6112b23f18d"
        "4d17e15e5eac5b9fe50e476fc2756edf",
    ),
    (
        b"hello",
        3,
        32,
        "aes",
        10,
        "bd2743566d2686663cb47aae39c67390"
        "beba138c87fd9447abb3ac2bfcddcaea",
    ),
    (bytes(range(12)), 4, 17, "aes", 10, "4c2aa3421b31a630bf61cbf98c5102eb64"),
    (
        b"A" * 15,
        0,
        33,
        "aes",
        10,
        "c6c55baed32f0413491fac5d6fca9ab1"
        "e31b3e3e0edeaf91cfedbf84c1d396fcec",
    ),
    (b"abc", 12, 6, "test", 4, "93434374f1c7"),
    (b"abc", 15, 7, "identity", 2, "bf985e62624ba7"),
    (bytes(range(4)), 12, 13, "aes", 1, "55c3de00753ad7cb1b65de5427"),
)


def _hashing():
    return importlib.import_module("educrypto.hashing")


def _sbox(name):
    return {
        "aes": _hashing().AES_SBOX,
        "test": TEST_SBOX,
        "identity": IDENTITY_SBOX,
    }[name]


def _expected_md_pad(message):
    bit_length = (len(message) * 8).to_bytes(16, "big")
    return message + b"\x80" + bytes((-len(message) - 1) % 16) + bit_length


def _expected_sponge_pad(message, c):
    rate = 16 - c
    padding_length = rate - len(message) % rate
    if padding_length == 1:
        return message + b"\x81"
    return message + b"\x80" + bytes(padding_length - 2) + b"\x01"


def _sponge_reference(message, *, c, digest_length, sbox, rounds):
    encrypt = importlib.import_module("educrypto.spn").encrypt_block
    xor = importlib.import_module("educrypto.encoding").xor_bytes
    rate = 16 - c
    padded = _expected_sponge_pad(message, c)
    state = bytes(16)
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        state = encrypt(
            bytes(range(16)),
            xor(state[:rate], block) + state[rate:],
            sbox=sbox,
            rounds=rounds,
        )
    output = bytearray()
    while len(output) < digest_length:
        output.extend(state[:rate])
        if len(output) < digest_length:
            state = encrypt(bytes(range(16)), state, sbox=sbox, rounds=rounds)
    return bytes(output[:digest_length])


def test_public_api_and_supplied_constants():
    module = _hashing()
    assert isinstance(module.AES_SBOX, bytes) and len(module.AES_SBOX) == 256
    assert hashlib.sha256(module.AES_SBOX).hexdigest() == (
        "c2d8e5eed6cbebd8625fc18f81486a7733c04f9b0129ffbe974c68b90308b4f2"
    )
    assert module.MD_IV == b"\xff" * 16
    assert module.SPONGE_KEY == bytes(range(16))

    expected = {
        "davies_meyer": ("data", "sbox", "rounds"),
        "merkle_damgard_pad": ("message",),
        "merkle_damgard": ("message", "sbox", "rounds"),
        "sponge_pad": ("message", "c"),
        "sponge_hash": ("message", "c", "digest_length", "sbox", "rounds"),
    }
    for name, names in expected.items():
        parameters = inspect.signature(getattr(module, name)).parameters
        assert tuple(parameters) == names
    for name in ("davies_meyer", "merkle_damgard", "sponge_hash"):
        parameters = inspect.signature(getattr(module, name)).parameters
        assert parameters["sbox"].default == module.AES_SBOX
        assert parameters["rounds"].default is inspect.Parameter.empty
    for name in ("davies_meyer", "merkle_damgard"):
        parameters = inspect.signature(getattr(module, name)).parameters
        assert all(
            parameter.kind is inspect.Parameter.KEYWORD_ONLY
            for parameter in tuple(parameters.values())[1:]
        )
    sponge_pad_parameters = inspect.signature(module.sponge_pad).parameters
    assert sponge_pad_parameters["c"].kind is inspect.Parameter.KEYWORD_ONLY
    assert sponge_pad_parameters["c"].default is inspect.Parameter.empty
    sponge_parameters = inspect.signature(module.sponge_hash).parameters
    assert all(
        sponge_parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        for name in ("c", "digest_length", "sbox", "rounds")
    )


@pytest.mark.parametrize(("sbox_name", "rounds", "expected_hex"), DM_VECTORS)
def test_davies_meyer_known_answers(sbox_name, rounds, expected_hex):
    result = _hashing().davies_meyer(H + M, sbox=_sbox(sbox_name), rounds=rounds)
    assert result == bytes.fromhex(expected_hex)
    assert isinstance(result, bytes) and len(result) == 16


def test_compression_roles_and_feed_forward():
    encrypted = importlib.import_module("educrypto.spn").encrypt_block(
        M, H, sbox=TEST_SBOX, rounds=4
    )
    expected = bytes(left ^ right for left, right in zip(encrypted, H))
    assert _hashing().davies_meyer(H + M, sbox=TEST_SBOX, rounds=4) == expected


@pytest.mark.parametrize(("length", "sbox_name", "rounds", "expected_hex"), MD_VECTORS)
def test_merkle_damgard_known_answers(length, sbox_name, rounds, expected_hex):
    message = bytes(index % 256 for index in range(length))
    result = _hashing().merkle_damgard(
        message, sbox=_sbox(sbox_name), rounds=rounds
    )
    assert result == bytes.fromhex(expected_hex)
    assert isinstance(result, bytes) and len(result) == 16


@pytest.mark.parametrize("length", (0, 1, 14, 15, 16, 17, 31, 32, 33, 80))
def test_merkle_damgard_strengthened_padding_and_chaining(length):
    module = _hashing()
    message = bytes(index % 256 for index in range(length))
    padded = module.merkle_damgard_pad(message)
    assert padded == _expected_md_pad(message)
    assert isinstance(padded, bytes)
    assert len(padded) % 16 == 0
    assert padded[-16:] == (length * 8).to_bytes(16, "big")
    assert padded[length] == 0x80
    assert padded[length + 1 : -16] == bytes(len(padded) - length - 17)
    if length == 0:
        assert len(padded) == 32
    if length == 16:
        assert len(padded) == 48

    state = module.MD_IV
    for offset in range(0, len(padded), 16):
        state = module.davies_meyer(
            state + padded[offset : offset + 16],
            sbox=TEST_SBOX,
            rounds=4,
        )
    assert module.merkle_damgard(message, sbox=TEST_SBOX, rounds=4) == state


@pytest.mark.parametrize(
    ("message", "c", "digest_length", "sbox_name", "rounds", "expected_hex"),
    SPONGE_VECTORS,
)
def test_sponge_known_answers(
    message, c, digest_length, sbox_name, rounds, expected_hex
):
    result = _hashing().sponge_hash(
        message,
        c=c,
        digest_length=digest_length,
        sbox=_sbox(sbox_name),
        rounds=rounds,
    )
    assert result == bytes.fromhex(expected_hex)
    assert isinstance(result, bytes) and len(result) == digest_length


@pytest.mark.parametrize(
    ("length", "c"),
    (
        (0, 0),
        (15, 0),       # one-byte 0x81 padding
        (16, 0),       # aligned message adds another block
        (0, 12),
        (2, 12),
        (3, 12),       # one-byte 0x81 padding
        (4, 12),       # aligned message adds another block
        (10, 15),
    ),
)
def test_public_sponge_padding(length, c):
    module = _hashing()
    message = bytes(index % 256 for index in range(length))
    padded = module.sponge_pad(message, c=c)
    assert padded == _expected_sponge_pad(message, c)
    assert isinstance(padded, bytes)
    assert padded.startswith(message)
    assert len(padded) % (16 - c) == 0


@pytest.mark.parametrize(
    ("length", "c", "digest_length"),
    (
        (0, 0, 1),
        (15, 0, 16),       # one-byte 0x81 padding
        (16, 0, 33),       # aligned message adds another block
        (2, 12, 19),
        (3, 12, 19),       # one-byte 0x81 padding
        (4, 12, 19),       # aligned message adds another block
        (10, 15, 7),
    ),
)
def test_sponge_absorption_padding_and_squeezing(length, c, digest_length):
    message = bytes(index % 256 for index in range(length))
    expected = _sponge_reference(
        message,
        c=c,
        digest_length=digest_length,
        sbox=TEST_SBOX,
        rounds=4,
    )
    assert _hashing().sponge_hash(
        message,
        c=c,
        digest_length=digest_length,
        sbox=TEST_SBOX,
        rounds=4,
    ) == expected


@pytest.mark.parametrize("c", (0, 4, 12, 15))
def test_sponge_output_prefixes_and_zero_length(c):
    module = _hashing()
    message = b"prefix property across partial and full squeeze blocks"
    rate = 16 - c
    long = module.sponge_hash(
        message, c=c, digest_length=2 * rate + 3, rounds=10
    )
    for length in (0, 1, rate, rate + 1, 2 * rate + 3):
        result = module.sponge_hash(
            message, c=c, digest_length=length, rounds=10
        )
        assert result == long[:length]


@pytest.mark.parametrize(("c", "digest_length"), ((-1, 1), (16, 1), (3, -1)))
def test_sponge_rejects_invalid_sizes(c, digest_length):
    with pytest.raises(ValueError):
        _hashing().sponge_hash(
            b"message", c=c, digest_length=digest_length, rounds=10
        )
    if c not in range(16):
        with pytest.raises(ValueError):
            _hashing().sponge_pad(b"message", c=c)


def test_defaults_calls_are_independent_and_inputs_are_preserved():
    module = _hashing()
    data, message, sbox = H + M, bytes(range(40)), TEST_SBOX
    snapshots = (
        data[:],
        message[:],
        sbox[:],
        module.MD_IV[:],
        module.SPONGE_KEY[:],
        module.AES_SBOX[:],
    )
    first_md = module.merkle_damgard(message, sbox=sbox, rounds=4)
    first_sponge = module.sponge_hash(
        message, c=4, digest_length=32, sbox=sbox, rounds=4
    )
    first_md_padding = module.merkle_damgard_pad(message)
    first_sponge_padding = module.sponge_pad(message, c=4)
    module.davies_meyer(data, rounds=10)
    module.sponge_hash(b"unrelated", c=12, digest_length=2, rounds=10)
    assert module.merkle_damgard(message, sbox=sbox, rounds=4) == first_md
    assert module.merkle_damgard_pad(message) == first_md_padding
    assert module.sponge_pad(message, c=4) == first_sponge_padding
    assert (
        module.sponge_hash(
            message, c=4, digest_length=32, sbox=sbox, rounds=4
        )
        == first_sponge
    )
    assert (
        data,
        message,
        sbox,
        module.MD_IV,
        module.SPONGE_KEY,
        module.AES_SBOX,
    ) == snapshots


@pytest.mark.attack
def test_solver_breaks_both_targets_and_recovers_unicode_secret():
    from course.week05.challenge.server import running_server

    secret = f"Week 05 {secrets.token_hex(24)} — π"
    attack = importlib.import_module("educrypto.attacks.week05")
    assert callable(attack.solve)
    with running_server(secret=secret) as server:
        recovered = attack.solve(server.base_url)
    assert isinstance(recovered, str)
    assert recovered == secret
