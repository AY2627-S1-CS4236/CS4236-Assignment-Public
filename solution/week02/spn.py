"""The configurable substitution-permutation network from Week 02."""

from __future__ import annotations

from .encoding import xor_bytes


BLOCK_SIZE = 16
STATE_BITS = BLOCK_SIZE * 8


def substitute(state: bytes, *, sbox: bytes) -> bytes:
    """Replace every state byte using the supplied S-box."""

    return bytes(sbox[value] for value in state)


def inverse_substitute(state: bytes, *, sbox: bytes) -> bytes:
    """Apply the inverse of the supplied S-box."""

    inverse = bytearray(256)
    for source, destination in enumerate(sbox):
        inverse[destination] = source
    return bytes(inverse[value] for value in state)


def _read_bit(state: bytes, position: int) -> int:
    byte_index, bit_index = divmod(position, 8)
    return (state[byte_index] >> (7 - bit_index)) & 1


def _write_bit(state: bytearray, position: int, value: int) -> None:
    byte_index, bit_index = divmod(position, 8)
    state[byte_index] |= value << (7 - bit_index)


def permute(state: bytes) -> bytes:
    """Move input bit i to output bit (13 * i + 17) modulo 128."""

    result = bytearray(BLOCK_SIZE)
    for source in range(STATE_BITS):
        destination = (13 * source + 17) % STATE_BITS
        _write_bit(result, destination, _read_bit(state, source))
    return bytes(result)


def inverse_permute(state: bytes) -> bytes:
    """Reverse the Week 02 bit permutation."""

    result = bytearray(BLOCK_SIZE)
    for destination in range(STATE_BITS):
        source = (13 * destination + 17) % STATE_BITS
        _write_bit(result, destination, _read_bit(state, source))
    return bytes(result)


def expand_key(
    key: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> tuple[bytes, ...]:
    """Produce the initial key followed by one key for each round."""

    round_keys = [key]
    for _ in range(rounds):
        previous = int.from_bytes(round_keys[-1], byteorder="big")
        rotated = (
            (previous >> 1) | ((previous & 1) << (STATE_BITS - 1))
        ).to_bytes(BLOCK_SIZE, byteorder="big")
        round_keys.append(substitute(rotated, sbox=sbox))
    return tuple(round_keys)


def encrypt_block(
    key: bytes,
    plaintext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    """Encrypt one 16-byte block."""

    round_keys = expand_key(key, sbox=sbox, rounds=rounds)
    state = xor_bytes(plaintext, round_keys[0])

    for round_key in round_keys[1:]:
        state = substitute(state, sbox=sbox)
        state = permute(state)
        state = xor_bytes(state, round_key)
    return state


def decrypt_block(
    key: bytes,
    ciphertext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    """Decrypt one 16-byte block."""

    round_keys = expand_key(key, sbox=sbox, rounds=rounds)
    state = ciphertext

    for round_key in reversed(round_keys[1:]):
        state = xor_bytes(state, round_key)
        state = inverse_permute(state)
        state = inverse_substitute(state, sbox=sbox)
    return xor_bytes(state, round_keys[0])
